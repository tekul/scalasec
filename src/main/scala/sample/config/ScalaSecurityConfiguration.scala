package sample.config

import sec._
import sec.Conversions._

import org.springframework.context.annotation.{Bean, Configuration}
import org.springframework.security.web.{FilterChainProxy, SecurityFilterChain}

/**
 * @author Luke Taylor
 */
@Configuration
class ScalaSecurityConfiguration {

  @Bean
  def filterChainProxy = {
    new FilterChainProxy(formLoginChain)
  }

  @Bean
  def formLoginChain: SecurityFilterChain = {
    val filterChain = new FilterChain with FormLogin with LoginPageGenerator {
      override def authenticationManager = testAuthenticationManager
    }

    filterChain.addInterceptUrl("/**", "ROLE_USER")
    filterChain
  }

  @Bean
  def basicFilterChain: SecurityFilterChain = {
    val filterChain = new FilterChain with BasicAuthentication with AnonymousAuthentication {
      override def authenticationManager = testAuthenticationManager
      addInterceptUrl("/**", "ROLE_USER")
    }
    filterChain
  }

  @Bean
  def testAuthenticationManager = {
    new AllowAllAuthenticationManager("ROLE_USER")
  }
}
