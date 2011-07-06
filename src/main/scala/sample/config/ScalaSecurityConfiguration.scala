package sample.config

import scalasec._
import scalasec.Conversions._

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
    new FilterChainProxy(formLoginWithScalaAccessRules)
  }

  /**
   * A form-login configuration with remember-me and other standard options
   */
  @Bean
  def simpleFormLoginChain: FilterChain = {
    new FilterChain with FormLogin with Logout with RememberMe with LoginPageGenerator {
      override val authenticationManager = testAuthenticationManager
      override val userDetailsService = testUserDetailsService
      interceptUrl("/", "IS_AUTHENTICATED_ANONYMOUSLY")
      interceptUrl("/**", "ROLE_USER")
    }
  }

  /**
   * A Basic authentication configuration
   */
  @Bean
  def basicFilterChain: SecurityFilterChain = {
    new FilterChain with BasicAuthentication {
      override val authenticationManager = testAuthenticationManager
      interceptUrl("/**", "ROLE_USER")
    }
  }

  /**
   * Simple AuthenticationManager setup for testing.
   */
  @Bean
  def testAuthenticationManager = {
    val provider = new DaoAuthenticationProvider
    provider.setUserDetailsService(testUserDetailsService)
    new ProviderManager(Arrays.asList(provider))
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
    new FilterChain with FormLogin with Logout with RememberMe with LoginPageGenerator {
      override val authenticationManager = testAuthenticationManager
      override val userDetailsService = testUserDetailsService
      interceptUrlScala("/", allowAnyone)
      interceptUrlScala("/scala*", allowAnyone)
      interceptUrlScala("/eventime*", allowOnEvenTime)
      interceptUrlScala("/**", allowAnyUser)
      override val accessDecisionVoters = new ScalaWebVoter :: Nil
    }
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
