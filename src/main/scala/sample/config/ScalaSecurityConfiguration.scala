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
 * An @Configuration with sample filter chains defined as separate beans
 *
 * @author Luke Taylor
 */
@Configuration
class ScalaSecurityConfiguration {

  /**
   * The FilterChainProxy bean which is delegated to from web.xml
   */
  @Bean
  def filterChainProxy = {
    new FilterChainProxy(simpleFormLoginChain)
  }

  /**
   * A form-login configuration with remember-me and other standard options
   */
  @Bean
  def simpleFormLoginChain: SecurityFilterChain = {
    val filterChain = new FilterChain with OpenID with Logout with RememberMe with LoginPageGenerator {
      override val authenticationManager = testAuthenticationManager
      override val userDetailsService = testUserDetailsService
      interceptUrl("/", "IS_AUTHENTICATED_ANONYMOUSLY")
      interceptUrl("/**", "ROLE_USER")
    }

    filterChain
  }

  /**
   * A Basic authentication configuration
   */
  @Bean
  def basicFilterChain: SecurityFilterChain = {
    val filterChain = new FilterChain with BasicAuthentication {
      override val authenticationManager = testAuthenticationManager
      interceptUrl("/**", "ROLE_USER")
    }
    filterChain
  }

  /**
   * Simple AuthenticationManager setup for testing.
   */
  @Bean
  def testAuthenticationManager = {
    val am = new ProviderManager()
    val provider = new DaoAuthenticationProvider
    provider.setUserDetailsService(testUserDetailsService)
    am.setProviders(Arrays.asList(provider))
    am
  }

  /**
   * Test UserDetailsService which accepts any username and returns a user object which has a password equal to the
   * username and which is assigned the single authority "ROLE_USER".
   */
  @Bean
  def testUserDetailsService = {
    new UserDetailsService {
      def loadUserByUsername(username: String) = new User(username, username, "ROLE_USER")
    }
  }

  /**
   * Form-login configuration which uses Scala functions as the access-control rules as a more powerful alternative
   * to EL.
   */
  @Bean
  def formLoginWithScalaAccessRules = {
    val filterChain = new FilterChain with FormLogin with Logout with RememberMe with LoginPageGenerator {
      override val authenticationManager = testAuthenticationManager
      override val userDetailsService = testUserDetailsService
      interceptUrlScala("/", allowAnyone)
      interceptUrlScala("/scala*", allowAnyone)
      interceptUrlScala("/eventime*", allowOnEvenTime)
      interceptUrlScala("/**", allowAnyUser)
      override val accessDecisionVoters = new ScalaWebVoter :: Nil
    }

    filterChain
  }

  // Some Scala access rules

  def allowAnyone(a: Authentication, r: HttpServletRequest) = {
    true
  }

  def allowAnyUser(a: Authentication, r: HttpServletRequest) = {
    a.getAuthorities.exists("ROLE_USER" == _.getAuthority)
  }

  def allowOnEvenTime(a: Authentication, r: HttpServletRequest) = {
    java.lang.System.currentTimeMillis() % 2 == 0
  }
}
