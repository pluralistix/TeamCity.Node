/*
 * Copyright 2013-2017 Eugene Petrenko
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.jonnyzzz.teamcity.plugins.node.agent.yarn

import com.jonnyzzz.teamcity.plugins.node.agent.processes.Execution
import com.jonnyzzz.teamcity.plugins.node.agent.processes.ScriptWrappingCommandLineGenerator
import com.jonnyzzz.teamcity.plugins.node.common.*
import jetbrains.buildServer.BuildProblemData
import jetbrains.buildServer.BuildProblemTypes
import jetbrains.buildServer.agent.*
import jetbrains.buildServer.agent.runner.*
import jetbrains.buildServer.serverSide.BuildTypeOptions
import org.apache.log4j.Logger

/**
 * Created by Florian Krauthan (mail@fkrauthan.de)
 * Date: 19.01.17
 */

class YarnServiceFactory : MultiCommandBuildSessionFactory {
  val bean = YarnBean()

  override fun createSession(p0: BuildRunnerContext): MultiCommandBuildSession = YarnSession(p0)

  override fun getBuildRunnerInfo(): AgentBuildRunnerInfo = object : AgentBuildRunnerInfo{
    override fun getType(): String = bean.runTypeName
    override fun canRun(agentConfiguration: BuildAgentConfiguration): Boolean = true
  }
}

class YarnSession(val runner : BuildRunnerContext) : MultiCommandBuildSession {
  private val bean = YarnBean()
  private var iterator : Iterator<YarnCommandExecution> = listOf<YarnCommandExecution>().iterator()
  private var previousStatus = BuildFinishedStatus.FINISHED_SUCCESS
  private val logger = runner.build.buildLogger.getFlowLogger(FlowGenerator.generateNewFlow())

  private fun resolveYarnExecutable() : String {
    val path = runner.runnerParameters[bean.toolPathKey]
    if (path == null || path.isEmptyOrSpaces()) return "yarn"
    return path.trim()
  }

  override fun sessionStarted() {
    logger.startFlow()

    val extra = runner.runnerParameters[bean.commandLineParameterKey].fetchArguments()
    val checkExitCode = runner.build.getBuildTypeOptionValue(BuildTypeOptions.BT_FAIL_ON_EXIT_CODE) ?: true
    val yarn = resolveYarnExecutable()

    iterator =
            bean.parseCommands(runner.runnerParameters[bean.yarnCommandsKey])
                    .map{ YarnCommandExecution(
                    logger,
                    "yarn $it",
                    runner,
                    Execution(yarn, extra + it.splitHonorQuotes())){ exitCode ->
                      previousStatus = when {
                        exitCode == 0 && checkExitCode -> BuildFinishedStatus.FINISHED_SUCCESS
                        else -> BuildFinishedStatus.FINISHED_WITH_PROBLEMS
                      }
                    }
            }.iterator()
  }

  override fun getNextCommand(): CommandExecution? =
          when {
            previousStatus != BuildFinishedStatus.FINISHED_SUCCESS -> null
            iterator.hasNext() -> iterator.next()
            else -> null
          }

  override fun sessionFinished(): BuildFinishedStatus {
    logger.disposeFlow()
    return previousStatus
  }
}

class YarnCommandExecution(val logger : BuildProgressLogger,
                                 val blockName : String,
                                 val runner : BuildRunnerContext,
                                 val cmd : Execution,
                                 val onFinished : (Int) -> Unit) : LoggingProcessListener(logger), CommandExecution {
  private val bean = YarnBean()
  private val OUT_LOG : Logger? = Logger.getLogger("teamcity.out")
  private val disposables = arrayListOf<() -> Unit>()

  override fun makeProgramCommandLine(): ProgramCommandLine =
          object:ScriptWrappingCommandLineGenerator<ProgramCommandLine>(runner) {
            override fun execute(executable: String, args: List<String>): ProgramCommandLine
                    = SimpleProgramCommandLine(build, executable, args)

            override fun disposeLater(action: () -> Unit) {
              disposables.add(action)
            }
          }.generate(cmd.program, cmd.arguments)


  override fun beforeProcessStarted() {
    logger.activityStarted(blockName, "yarn");
  }

  override fun onStandardOutput(text: String) {
    if (text.contains("yarn ERR!")){
      logger.error(text)
      OUT_LOG?.warn(text)
      return
    }
    super.onStandardOutput(text)
  }

  override fun onErrorOutput(text: String) {
    if (text.contains("yarn ERR!")){
      logger.error(text)
      OUT_LOG?.warn(text)
      return
    }
    super.onErrorOutput(text)
  }

  override fun processFinished(exitCode: Int) {
    super.processFinished(exitCode)

    if (exitCode != 0) {
      logger.logBuildProblem(createExitCodeBuildProblem(exitCode))
    }

    logger.activityFinished(blockName, "yarn");
    disposables.forEach { it() }
    onFinished(exitCode)
  }

  // copy of jetbrains.buildServer.agent.runner.CommandLineBuildService.createExitCodeBuildProblem for backward compatibility
  private fun createExitCodeBuildProblem(exitCode: Int): BuildProblemData {
    return BuildProblemData.createBuildProblem(
            bean.runTypeName + exitCode,
            BuildProblemTypes.TC_EXIT_CODE_TYPE,
            "Process exited with code " + exitCode, "teamcity.process.flow.id=" + logger.flowId)
  }

  override fun interruptRequested(): TerminationAction = TerminationAction.KILL_PROCESS_TREE
  override fun isCommandLineLoggingEnabled(): Boolean = true
}
