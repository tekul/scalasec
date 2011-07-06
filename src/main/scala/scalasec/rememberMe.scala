package scalasec

import org.springframework.security.web.authentication.rememberme._
import org.springframework.security.web.authentication.RememberMeServices
import org.springframework.security.authentication.RememberMeAuthenticationProvider

/**
 * @author Luke Taylor
 */
trait RememberMe extends StatelessFilterChain with UserService {
  val rememberMeKey = "todo"

  override lazy val rememberMeFilter = new RememberMeAuthenticationFilter(internalAuthenticationManager, rememberMeServices)

  val rememberMeProvider = new RememberMeAuthenticationProvider(rememberMeKey)

  override lazy val rememberMeServices: RememberMeServices = new TokenBasedRememberMeServices(rememberMeKey, userDetailsService)

  override def authenticationProviders = {
    rememberMeProvider :: super.authenticationProviders
  }
}

trait PersistentRememberMe extends RememberMe {
  lazy val tokenRepository : PersistentTokenRepository = new InMemoryTokenRepositoryImpl

  override lazy val rememberMeServices =
    new PersistentTokenBasedRememberMeServices(rememberMeKey, userDetailsService, tokenRepository)
}
