package sample.config

import sec._
import sec.Conversions._

import org.springframework.context.annotation.{Bean, Configuration}
import org.springframework.security.web.{FilterChainProxy, SecurityFilterChain}
import org.springframework.security.core.userdetails.{User, UserDetailsService}
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import java.util.Arrays

/**
 * @author Luke Taylor
 */
@Configuration
class ScalaSecurityConfiguration {

  @Bean
  def filterChainProxy = {
    new FilterChainProxy(simpleFormLoginChain)
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
  def testUserDetailsService = {
    new UserDetailsService {
      def loadUserByUsername(username: String) = new User(username, username, "ROLE_USER")
    }
  }
}
