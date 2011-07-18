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

import FilterPositions._

/**
 * Encapsulates the internal ProviderManager and AuthenticationProviders user by the
 * filter authentication mechanisms, as well as the reference to the parent
 * AuthenticationManager which the user must define.
 */
private[scalasec] trait FilterChainAuthenticationManager {
  private[scalasec] def authenticationProviders : List[AuthenticationProvider] = Nil

  private[scalasec] lazy val internalAuthenticationManager : ProviderManager =
    new ProviderManager(Arrays.asList(authenticationProviders:_*), authenticationManager)

  val authenticationManager : AuthenticationManager
}

/**
 * @author Luke Taylor
 */
trait AnonymousAuthentication extends StatelessFilterChain with FilterChainAuthenticationManager {
  val anonymousKey = "replaceMeWithAProperKey"
  val anonymousProvider = new AnonymousAuthenticationProvider(anonymousKey)

  override def authenticationProviders = anonymousProvider :: super.authenticationProviders

  lazy val anonymousFilter = new AnonymousAuthenticationFilter(anonymousKey)

  override def filtersInternal = (ANONYMOUS_FILTER, anonymousFilter) :: super.filtersInternal
}

trait Logout extends StatelessFilterChain with RememberMeServicesAware {
  lazy val logoutHandlers: List[LogoutHandler] = {
    val sclh = new SecurityContextLogoutHandler()
    rememberMeServices match {
      case l: LogoutHandler =>  sclh :: l :: Nil
      case _ => sclh :: Nil
    }
  }
  val logoutSuccessHandler : LogoutSuccessHandler = new SimpleUrlLogoutSuccessHandler()
  lazy val logoutFilter = new LogoutFilter(logoutSuccessHandler, logoutHandlers : _*)

  override def filtersInternal = (LOGOUT_FILTER, logoutFilter) :: super.filtersInternal
}

private[scalasec] trait LoginPage extends StatelessFilterChain {
  val loginPage: String

  override def entryPoint : AuthenticationEntryPoint = {
    new LoginUrlAuthenticationEntryPoint(loginPage)
  }
}

/**
 * Automatically generates a login page for form-login.
 */
trait LoginPageGenerator extends StatelessFilterChain with FormLogin {
  override val loginPage = "/spring_security_login"

  lazy val loginPageFilter = new DefaultLoginPageGeneratingFilter(formLoginFilter.asInstanceOf[UsernamePasswordAuthenticationFilter])

  override def filtersInternal = (LOGIN_PAGE_FILTER, loginPageFilter) :: super.filtersInternal
}

trait FormLogin extends StatelessFilterChain with EventPublisher
    with LoginPage
    with RememberMeServicesAware
    with SessionAuthentication
    with FilterChainAuthenticationManager {

  lazy val formLoginFilter = {
    val filter = new UsernamePasswordAuthenticationFilter
    filter.setAuthenticationManager(authenticationManager)
    filter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy)
    filter.setRememberMeServices(rememberMeServices)
    filter.setApplicationEventPublisher(eventPublisher)
    filter
  }

  override def filtersInternal = (FORM_LOGIN_FILTER, formLoginFilter) :: super.filtersInternal
}

trait OpenID extends StatelessFilterChain with EventPublisher
    with LoginPage
    with SessionAuthentication
    with RememberMeServicesAware
    with UserService
    with FilterChainAuthenticationManager {

  lazy val openIDFilter = {
    val filter = new OpenIDAuthenticationFilter
    filter.setConsumer(new OpenID4JavaConsumer)
    filter.setRememberMeServices(rememberMeServices)
    filter.setAuthenticationManager(internalAuthenticationManager)
    filter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy)
    filter.setApplicationEventPublisher(eventPublisher)
    filter
  }
  lazy val openIDProvider = {
    val provider = new OpenIDAuthenticationProvider
    provider.setUserDetailsService(userDetailsService)
    provider
  }

  override def authenticationProviders = openIDProvider :: super.authenticationProviders

  override def filtersInternal = (OPENID_FILTER, openIDFilter) :: super.filtersInternal
}

trait BasicAuthentication extends StatelessFilterChain with FilterChainAuthenticationManager {
  val basicAuthenticationEntryPoint = new BasicAuthenticationEntryPoint()

  lazy val basicAuthenticationFilter =
    new BasicAuthenticationFilter(authenticationManager, basicAuthenticationEntryPoint)

  override def entryPoint : AuthenticationEntryPoint = basicAuthenticationEntryPoint

  override def filtersInternal = (BASIC_AUTH_FILTER, basicAuthenticationFilter) :: super.filtersInternal
}

private[scalasec] sealed trait RememberMeServicesAware {
  lazy val rememberMeServices: RememberMeServices = new NullRememberMeServices
}

trait RememberMe extends StatelessFilterChain
    with RememberMeServicesAware
    with EventPublisher
    with UserService
    with FilterChainAuthenticationManager {

  val rememberMeKey = "todo"

  lazy val rememberMeFilter = {
    val filter = new RememberMeAuthenticationFilter(internalAuthenticationManager, rememberMeServices)
    filter.setApplicationEventPublisher(eventPublisher)
    filter
  }

  val rememberMeProvider = new RememberMeAuthenticationProvider(rememberMeKey)

  override lazy val rememberMeServices: RememberMeServices = new TokenBasedRememberMeServices(rememberMeKey, userDetailsService)

  override def authenticationProviders = rememberMeProvider :: super.authenticationProviders

  override def filtersInternal = (REMEMBER_ME_FILTER, rememberMeFilter) :: super.filtersInternal
}

trait PersistentRememberMe extends RememberMe {
  lazy val tokenRepository : PersistentTokenRepository = new InMemoryTokenRepositoryImpl

  override lazy val rememberMeServices =
    new PersistentTokenBasedRememberMeServices(rememberMeKey, userDetailsService, tokenRepository)
}
