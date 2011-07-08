package scalasec

import org.springframework.security.web.authentication.logout._
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter
import org.springframework.security.openid.{OpenIDAuthenticationProvider, OpenID4JavaConsumer, OpenIDAuthenticationFilter}
import org.springframework.security.web.authentication.www.{BasicAuthenticationFilter, BasicAuthenticationEntryPoint}
import org.springframework.security.web.authentication._
import org.springframework.security.authentication._
import java.util.Arrays
import rememberme._

/**
 * Encapsulates the internal ProviderManager and AuthenticationProviders user by the
 * filter authentication mechanisms, as well as the reference to the parent
 * AuthenticationManager which the user must define.
 */
private[scalasec] trait FilterChainAuthenticationManager {
  private[scalasec] def authenticationProviders : List[AuthenticationProvider] = Nil

  private[scalasec] lazy val internalAuthenticationManager : ProviderManager = {
    new ProviderManager(Arrays.asList(authenticationProviders:_*), authenticationManager)
  }
  val authenticationManager : AuthenticationManager
}

/**
 * @author Luke Taylor
 */
trait AnonymousAuthentication extends StatelessFilterChain with FilterChainAuthenticationManager {
  val anonymousKey = "replaceMeWithAProperKey"
  val anonymousProvider = new AnonymousAuthenticationProvider(anonymousKey)

  override def authenticationProviders = {
    anonymousProvider :: super.authenticationProviders
  }

  override lazy val anonymousFilter = new AnonymousAuthenticationFilter(anonymousKey)
}

trait Logout extends StatelessFilterChain {
  lazy val logoutHandlers: List[LogoutHandler] = {
    val sclh = new SecurityContextLogoutHandler()
    rememberMeServices match {
      case l: LogoutHandler =>  sclh :: l :: Nil
      case _ => sclh :: Nil
    }
  }
  val logoutSuccessHandler : LogoutSuccessHandler = new SimpleUrlLogoutSuccessHandler()
  override lazy val logoutFilter = new LogoutFilter(logoutSuccessHandler, logoutHandlers : _*)
}

private[scalasec] trait LoginPage extends StatelessFilterChain {
  val loginPage: String = null

  override def entryPoint : AuthenticationEntryPoint = {
    assert(loginPage != null, "You need to set the loginPage value or add the LoginPageGenerator trait")
    new LoginUrlAuthenticationEntryPoint(loginPage)
  }
}

trait LoginPageGenerator extends StatelessFilterChain with LoginPage {
  override val loginPage = "/spring_security_login"

  override lazy val loginPageFilter = {
    new DefaultLoginPageGeneratingFilter(formLoginFilter.asInstanceOf[UsernamePasswordAuthenticationFilter],
      openIDFilter.asInstanceOf[AbstractAuthenticationProcessingFilter])
  }
}

trait FormLogin extends StatelessFilterChain with LoginPage with FilterChainAuthenticationManager {
  override lazy val formLoginFilter = {
    val filter = new UsernamePasswordAuthenticationFilter
    filter.setAuthenticationManager(authenticationManager)
    filter.setRememberMeServices(rememberMeServices)
    filter
  }
}

trait OpenID extends StatelessFilterChain with LoginPage with UserService with FilterChainAuthenticationManager {
  override lazy val openIDFilter = {
    val filter = new OpenIDAuthenticationFilter
    filter.setConsumer(new OpenID4JavaConsumer)
    filter.setRememberMeServices(rememberMeServices)
    filter.setAuthenticationManager(internalAuthenticationManager)
    filter
  }
  lazy val openIDProvider = {
    val provider = new OpenIDAuthenticationProvider
    provider.setUserDetailsService(userDetailsService)
    provider
  }

  override def authenticationProviders = {
    openIDProvider :: super.authenticationProviders
  }
}

trait BasicAuthentication extends StatelessFilterChain with FilterChainAuthenticationManager {
  val basicAuthenticationEntryPoint = new BasicAuthenticationEntryPoint()

  override lazy val basicAuthenticationFilter =
    new BasicAuthenticationFilter(authenticationManager, basicAuthenticationEntryPoint)

  override def entryPoint : AuthenticationEntryPoint = basicAuthenticationEntryPoint
}

trait RememberMe extends StatelessFilterChain with UserService with FilterChainAuthenticationManager {
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
