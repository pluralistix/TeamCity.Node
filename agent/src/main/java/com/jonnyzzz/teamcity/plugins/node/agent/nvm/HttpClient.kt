/*
 * Copyright 2013-2015 Eugene Petrenko
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

package com.jonnyzzz.teamcity.plugins.node.agent.nvm

import com.jonnyzzz.teamcity.plugins.node.common.log4j
import jetbrains.buildServer.serverSide.TeamCityProperties
import jetbrains.buildServer.version.ServerVersionHolder
import org.apache.http.HttpException
import org.apache.http.HttpHost
import org.apache.http.HttpRequest
import org.apache.http.HttpResponse
import org.apache.http.auth.AuthScope
import org.apache.http.auth.Credentials
import org.apache.http.auth.NTCredentials
import org.apache.http.auth.UsernamePasswordCredentials
import org.apache.http.client.HttpClient
import org.apache.http.client.config.RequestConfig
import org.apache.http.client.methods.HttpUriRequest
import org.apache.http.config.RegistryBuilder
import org.apache.http.conn.routing.HttpRoute
import org.apache.http.conn.socket.ConnectionSocketFactory
import org.apache.http.conn.socket.PlainConnectionSocketFactory
import org.apache.http.conn.ssl.SSLConnectionSocketFactory
import org.apache.http.conn.ssl.SSLContexts
import org.apache.http.conn.ssl.X509HostnameVerifier
import org.apache.http.impl.client.BasicCredentialsProvider
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler
import org.apache.http.impl.client.HttpClients
import org.apache.http.impl.conn.DefaultProxyRoutePlanner
import org.apache.http.impl.conn.DefaultRoutePlanner
import org.apache.http.impl.conn.DefaultSchemePortResolver
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager
import org.apache.http.protocol.HttpContext
import org.springframework.beans.factory.DisposableBean
import java.io.IOException
import java.security.KeyManagementException
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocket

/**
 * @author Eugene Petrenko (eugene.petrenko@gmail.com)
 * Date: 13.08.13 22:43
 */
interface HttpClientWrapper {
    fun <T> execute(request: HttpUriRequest, action: HttpResponse.() -> T): T
}

/**
 * Created by Eugene Petrenko (eugene.petrenko@gmail.com)
 * Date: 11.08.11 16:24
 */
class HttpClientWrapperImpl : HttpClientWrapper, DisposableBean {
    private val logger = log4j(NVMDownloader::class.java)

    private val myClient: HttpClient
    private var myConnectionManager: PoolingHttpClientConnectionManager? = null

    init {
        val serverVersion = ServerVersionHolder.getVersion().displayVersion
        val myRegistries = RegistryBuilder
                .create<ConnectionSocketFactory>().register("http", PlainConnectionSocketFactory.INSTANCE)
        if (!TeamCityProperties.getBoolean("teamcity.node.verify.ssl.certificate")) {
            val builder = SSLContexts.custom()
            try {
                builder.loadTrustMaterial(null) { chain, authType -> true }
            } catch (e: NoSuchAlgorithmException) {
                e.printStackTrace()
            } catch (e: KeyStoreException) {
                e.printStackTrace()
            }

            var sslContext: SSLContext? = null
            try {
                sslContext = builder.build()
            } catch (e: NoSuchAlgorithmException) {
                e.printStackTrace()
            } catch (e: KeyManagementException) {
                e.printStackTrace()
            }

            val sslConnectionSocketFactory = SSLConnectionSocketFactory(
                    sslContext!!, object : X509HostnameVerifier {
                @Throws(IOException::class)
                override fun verify(host: String, ssl: SSLSocket) {
                }

                @Throws(SSLException::class)
                override fun verify(host: String, cert: X509Certificate) {
                }

                @Throws(SSLException::class)
                override fun verify(host: String, cns: Array<String>,
                                    subjectAlts: Array<String>) {
                }

                override fun verify(s: String, sslSession: SSLSession): Boolean {
                    return true
                }
            })

            myConnectionManager = PoolingHttpClientConnectionManager(myRegistries.register("https", sslConnectionSocketFactory)
                    .build())
        } else {
            myConnectionManager = PoolingHttpClientConnectionManager()
        }

        val routePlanner = object : DefaultRoutePlanner(DefaultSchemePortResolver.INSTANCE) {
            @Throws(HttpException::class)
            override fun determineRoute(host: HttpHost, request: HttpRequest, context: HttpContext): HttpRoute {
                return super.determineRoute(host, request, context)
            }
        }

        val hcBuilder = HttpClients.custom()
                .setConnectionManager(myConnectionManager)
                .setRoutePlanner(routePlanner)
                .setUserAgent("JetBrains TeamCity $serverVersion")
                .setDefaultRequestConfig(
                        RequestConfig.custom()
                                .setSocketTimeout(300 * 1000)
                                .setConnectTimeout(300 * 1000)
                                .setConnectionRequestTimeout(5000)
                                .build())
                .setRetryHandler(DefaultHttpRequestRetryHandler(3, true))

        hcBuilder.setRoutePlanner(routePlanner)

        val prefix = "teamcity.http.proxy."
        val suffix = ".node"

        val proxyHost = TeamCityProperties.getPropertyOrNull(prefix + "host" + suffix)
        val proxyPort = TeamCityProperties.getInteger(prefix + "port" + suffix, 3128)

        val proxyDomain = TeamCityProperties.getPropertyOrNull(prefix + "domain" + suffix)
        val proxyUser = TeamCityProperties.getPropertyOrNull(prefix + "user" + suffix)
        val proxyPassword = TeamCityProperties.getPropertyOrNull(prefix + "password" + suffix)
        val proxyWorkstation = TeamCityProperties.getPropertyOrNull(prefix + "workstation" + suffix)

        if (proxyHost != null && proxyPort > 0) {
            hcBuilder.setRoutePlanner(DefaultProxyRoutePlanner(HttpHost(proxyHost, proxyPort)))

            if (proxyUser != null && proxyPassword != null) {
                val credentialsProvider = BasicCredentialsProvider()
                if (proxyDomain != null || proxyWorkstation != null) {
                    logger.info("TeamCity.Node.NVM. Using HTTP proxy $proxyHost:$proxyPort, username: ${proxyDomain
                            ?: proxyWorkstation ?: "."}\\$proxyUser")
                    credentialsProvider.setCredentials(AuthScope(proxyHost, proxyPort), UsernamePasswordCredentials(proxyUser, proxyPassword) as Credentials)
                } else {
                    logger.info("TeamCity.Node.NVM. Using HTTP proxy $proxyHost:$proxyPort, username: $proxyUser")
                    credentialsProvider.setCredentials(AuthScope(proxyHost, proxyPort), NTCredentials(proxyUser, proxyPassword, proxyWorkstation, proxyDomain) as Credentials)
                }
            } else {
                logger.info("TeamCity.Node.NVM. Using HTTP proxy $proxyHost:$proxyPort")
            }
        }

        myClient = hcBuilder.build()
    }

    override fun <T> execute(request: HttpUriRequest, action: HttpResponse.() -> T): T {
        val response = myClient.execute(request)!!
        try {
            return response.action()
        } finally {
            request.abort()
        }
    }


    override fun destroy() {
        myConnectionManager!!.shutdown()
    }
}

