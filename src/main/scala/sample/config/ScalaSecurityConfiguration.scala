package sample.config

import scalasec._

import org.springframework.context.annotation.{Bean, Configuration}
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.util.IpAddressMatcher
import org.springframework.security.core.userdetails.{User, UserDetailsService}
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import java.util.Arrays
import javax.servlet.http.HttpServletRequest
import org.springframework.security.core.Authentication

import org.springframework.security.authentication.{DefaultAuthenticationEventPublisher, ProviderManager}

import scalasec.WebAccessRules._

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
   * A form-login configuration with remember-me and other standard options.
   * Namespace equivalent would be:
   * <pre>
   *   &lt;http use-expressions="true">
   *     &lt;intercept-url pattern="/" access="permitAll" />
   *     &lt;intercept-url pattern="/&#42*" access="hasRole('ROLE_USER')" />
   *     &lt;form-login />
   *     &lt;logout />
   *     &lt;remember-me />
   *   &lt;/http>
   * </pre>
   */
  @Bean
  def simpleFormLoginChain: FilterChain = {
    new FilterChain with FormLogin with Logout with RememberMe with LoginPageGenerator {
      val authenticationManager = testAuthenticationManager
      val userDetailsService = testUserDetailsService
      interceptUrl("/", permitAll)
      interceptUrl("/**", hasRole("ROLE_USER"))
    }
  }

  /**
   * A Basic authentication configuration
   */
  @Bean
  def basicFilterChain: FilterChain = {
    new FilterChain with BasicAuthentication {
      val authenticationManager = testAuthenticationManager
      interceptUrl("/**", hasRole("ROLE_USER"))
    }
  }

  /**
   * Simple AuthenticationManager setup for testing.
   */
  @Bean
  def testAuthenticationManager = {
    val provider = new DaoAuthenticationProvider
    provider.setUserDetailsService(testUserDetailsService)
    val am = new ProviderManager(Arrays.asList(provider))
    am.setAuthenticationEventPublisher(authenticationEventPublisher)
    am
  }

  @Bean
  def authenticationEventPublisher = {
    new DefaultAuthenticationEventPublisher
  }

  /**
   * Test UserDetailsService which accepts any username and returns a user object which has a password equal to the
   * username and which is assigned the single authority "ROLE_USER".
   */
  @Bean
  def testUserDetailsService = {
    import scalasec.Conversions._

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
      val authenticationManager = testAuthenticationManager
      val userDetailsService = testUserDetailsService
      interceptUrl("/", permitAll)
      interceptUrl("/scala*", permitAll)
      interceptUrl("/onlylocal*", isLocalhost)
      interceptUrl("/eventime*", allowOnEvenTime)
      interceptUrl("/**", hasRole("ROLE_USER"))
    }
  }

  // Some access rules
  def allowOnEvenTime(a: Authentication, r: HttpServletRequest) = {
    java.lang.System.currentTimeMillis() % 2 == 0
  }

  val localhostMatcher = new IpAddressMatcher("127.0.0.1")

  def isLocalhost(a: Authentication, r: HttpServletRequest) = {
    localhostMatcher.matches(r)
  }
}
