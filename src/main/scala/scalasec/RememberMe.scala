package scalasec

import org.springframework.security.web.authentication.rememberme._
import org.springframework.security.web.authentication.RememberMeServices
import org.springframework.security.authentication.RememberMeAuthenticationProvider

/**
 * @author Luke Taylor
 */
trait RememberMe extends StatelessFilterChain with UserService {
  val rememberMeKey = "todo"

  override lazy val rememberMeFilter = {
    val filter = new RememberMeAuthenticationFilter
    filter.setAuthenticationManager(internalAuthenticationManager)
    filter.setRememberMeServices(rememberMeServices)
    filter
  }

  lazy val rememberMeProvider = {
    val provider = new RememberMeAuthenticationProvider
    provider.setKey(rememberMeKey)
    provider
  }

  override lazy val rememberMeServices: RememberMeServices = {
    val rm = new TokenBasedRememberMeServices
    rm.setKey(rememberMeKey)
    rm.setUserDetailsService(userDetailsService)
    rm
  }

  override def authenticationProviders = {
    rememberMeProvider :: super.authenticationProviders
  }
}

trait PersistentRememberMe extends RememberMe {
  lazy val tokenRepository : PersistentTokenRepository = new InMemoryTokenRepositoryImpl

  override lazy val rememberMeServices = {
    val rm = new PersistentTokenBasedRememberMeServices
    rm.setTokenRepository(tokenRepository)
    rm
  }
}
