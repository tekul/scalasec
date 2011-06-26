package sample.config

import sec._
import sec.Conversions._

import org.springframework.context.annotation.{Bean, Configuration}
import org.springframework.security.web.{FilterChainProxy, SecurityFilterChain}
import org.springframework.security.core.userdetails.{User, UserDetailsService}
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import java.util.Arrays
import javax.servlet.http.HttpServletRequest
import org.springframework.security.core.Authentication

import scala.collection.JavaConversions._

/**
 * @author Luke Taylor
 */
@Configuration
class ScalaSecurityConfiguration {

  @Bean
  def filterChainProxy = {
    new FilterChainProxy(formLoginWithScalaAccessRules)
  }

  @Bean
  def simpleFormLoginChain: SecurityFilterChain = {
    val filterChain = new FilterChain with FormLogin with Logout with RememberMe with LoginPageGenerator {
      override def authenticationManager = testAuthenticationManager
      override val userDetailsService = testUserDetailsService
      interceptUrl("/", "IS_AUTHENTICATED_ANONYMOUSLY")
      interceptUrl("/**", "ROLE_USER")
    }

    filterChain
  }

  @Bean
  def basicFilterChain: SecurityFilterChain = {
    val filterChain = new FilterChain with BasicAuthentication with AnonymousAuthentication {
      override def authenticationManager = testAuthenticationManager
      interceptUrl("/**", "ROLE_USER")
    }
    filterChain
  }

  @Bean
  def testAuthenticationManager = {
    val am = new ProviderManager()
    val provider = new DaoAuthenticationProvider
    provider.setUserDetailsService(testUserDetailsService)
    am.setProviders(Arrays.asList(provider))
    am.setEraseCredentialsAfterAuthentication(false)
    am
  }

  @Bean
  def formLoginWithScalaAccessRules = {
    val filterChain = new FilterChain with FormLogin with Logout with RememberMe with LoginPageGenerator {
      override def authenticationManager = testAuthenticationManager
      override val userDetailsService = testUserDetailsService
      interceptUrlScala("/", allowAnyone)
      interceptUrlScala("/scala*", allowAnyone)
      interceptUrlScala("/**", allowAnyUser)
      override val accessDecisionVoters = new ScalaWebVoter :: Nil
    }

    filterChain
  }

  // Access rules
  def allowAnyone(a: Authentication, r: HttpServletRequest) = {
    true
  }

  def allowAnyUser(a: Authentication, r: HttpServletRequest) = {
    a.getAuthorities.exists("ROLE_USER" == _.getAuthority)
  }

  @Bean
  def testUserDetailsService = {
    new UserDetailsService {
      def loadUserByUsername(username: String) = new User(username, username, "ROLE_USER")
    }
  }
}
