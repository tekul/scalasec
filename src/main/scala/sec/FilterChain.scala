package sec

import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.authentication.www.{BasicAuthenticationEntryPoint, BasicAuthenticationFilter}
import org.springframework.security.web.util.RequestMatcher
import org.springframework.security.web.access.intercept.{DefaultFilterInvocationSecurityMetadataSource, FilterInvocationSecurityMetadataSource, FilterSecurityInterceptor}
import org.springframework.security.web.authentication.logout._
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
import collection.immutable.ListMap

import javax.servlet.Filter

import java.{util => ju}
import org.springframework.security.web.session.SessionManagementFilter
import org.springframework.security.core.userdetails.memory.UserAttribute
import java.util.Arrays
import org.springframework.security.access.{AccessDecisionManager, AccessDecisionVoter, SecurityConfig, ConfigAttribute}
import org.springframework.security.access.vote.{AffirmativeBased, AuthenticatedVoter, RoleVoter}
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.authentication.{AuthenticationManager, ProviderManager, AnonymousAuthenticationProvider, AuthenticationProvider}
import org.springframework.security.web.context.{SecurityContextRepository, NullSecurityContextRepository, HttpSessionSecurityContextRepository, SecurityContextPersistenceFilter}
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter
import org.springframework.security.web.authentication._
import org.springframework.security.openid.{OpenIDAuthenticationProvider, OpenIDAuthenticationFilter}
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.savedrequest.{RequestCache, HttpSessionRequestCache, NullRequestCache, RequestCacheAwareFilter}
import javax.servlet.http.HttpServletRequest
import org.springframework.security.core.Authentication
import org.springframework.security.web.access.expression.{WebExpressionVoter, DefaultWebSecurityExpressionHandler, ExpressionBasedFilterInvocationSecurityMetadataSource}

object RequiredChannel extends Enumeration {
  val Http, Https, Any = Value
}

abstract class FilterChain extends StatelessFilterChain with AnonymousAuthentication {
  override val securityContextRepository = new HttpSessionSecurityContextRepository

  override val requestCache = new HttpSessionRequestCache

  override lazy val requestCacheFilter = {
    val filter = new RequestCacheAwareFilter()
    filter.setRequestCache(requestCache)
    filter
  }

  override lazy val sessionManagementFilter : Filter = {
    new SessionManagementFilter(securityContextRepository)
  }
}

/**
 * Todo. Add constructor injection to filters in spring sec (Anon, Fsi etc).
 *
 * @author Luke Taylor
 */
abstract class StatelessFilterChain extends FilterStack with Conversions {
  // Controls which requests will be handled by this filter chain
  val requestMatcher : RequestMatcher = "/**"

  override lazy val securityContextPersistenceFilter = {
    val scpf = new SecurityContextPersistenceFilter
    scpf.setSecurityContextRepository(securityContextRepository)
    scpf
  }

  val securityContextRepository : SecurityContextRepository = new NullSecurityContextRepository

  override lazy val servletApiFilter = new SecurityContextHolderAwareRequestFilter()

  val requestCache: RequestCache = new NullRequestCache

  override lazy val exceptionTranslationFilter = {
    val etf = new ExceptionTranslationFilter
    etf.setAuthenticationEntryPoint(entryPoint)
    etf.setRequestCache(requestCache)
    etf
  }

  def entryPoint : AuthenticationEntryPoint = new Http403ForbiddenEntryPoint

  override lazy val filterSecurityInterceptor = {
    val fsi = new FilterSecurityInterceptor()
    fsi.setSecurityMetadataSource(securityMetadataSource)
    fsi.setAccessDecisionManager(accessDecisionManager)
    fsi
  }

  private var channels : ListMap[RequestMatcher, RequiredChannel.Value] = ListMap()
  private[sec] var accessUrls : ListMap[RequestMatcher, ju.List[ConfigAttribute]] = ListMap()
  private[sec] def securityMetadataSource : FilterInvocationSecurityMetadataSource
          = new DefaultFilterInvocationSecurityMetadataSource(accessUrls)

  def interceptUrl(matcher: RequestMatcher, access: String, channel: RequiredChannel.Value = RequiredChannel.Any) {
    addInterceptUrl(matcher, SecurityConfig.createList(access.split(",") : _*), channel)
  }

  def interceptUrlScala(matcher: RequestMatcher, access: (Authentication, HttpServletRequest) => Boolean, channel: RequiredChannel.Value = RequiredChannel.Any) {
    addInterceptUrl(matcher, Arrays.asList(new ScalaWebConfigAttribute(access)), channel)
  }

  private[sec] def addInterceptUrl(matcher: RequestMatcher, attributes: ju.List[ConfigAttribute], channel: RequiredChannel.Value) {
    assert(!accessUrls.contains(matcher), "An identical RequestMatcher already exists: " + matcher)
    accessUrls = accessUrls + (matcher -> attributes)
    channels = channels + (matcher -> channel)
  }

  def accessDecisionVoters : List[AccessDecisionVoter[_]] = List(new RoleVoter(), new AuthenticatedVoter())

  lazy val accessDecisionManager : AccessDecisionManager = {
    val adm = new AffirmativeBased
    adm.setDecisionVoters(Arrays.asList(accessDecisionVoters: _*))
    adm
  }

  private[sec] def authenticationProviders : List[AuthenticationProvider] = Nil

  private[sec] lazy val internalAuthenticationManager : ProviderManager = {
    val am = new ProviderManager
    am.setParent(authenticationManager)
    am.setProviders(Arrays.asList(authenticationProviders:_*))
    am
  }

  lazy val rememberMeServices: RememberMeServices = new NullRememberMeServices

  def authenticationManager : AuthenticationManager
}

trait AnonymousAuthentication extends StatelessFilterChain {
  lazy val anonymousKey = "replaceMeWithAProperKey"
  def anonymousProvider = {
    val p = new AnonymousAuthenticationProvider
    p.setKey(anonymousKey)
    p
  }
  val user = {
    val attribute = new UserAttribute()
    attribute.setPassword("anonymous")
    attribute.setAuthorities("ROLE_ANONYMOUS")
    attribute
  }

  override def authenticationProviders = {
    anonymousProvider :: super.authenticationProviders
  }

  override lazy val anonymousFilter = {
    val filter = new AnonymousAuthenticationFilter
    filter.setKey(anonymousKey)
    filter.setUserAttribute(user)

    filter
  }
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

trait ELAccessControl extends StatelessFilterChain {
  val expressionHandler = new DefaultWebSecurityExpressionHandler()

  override lazy val securityMetadataSource = new ExpressionBasedFilterInvocationSecurityMetadataSource(accessUrls, expressionHandler)

  override def interceptUrl(matcher: RequestMatcher, access: String, channel: RequiredChannel.Value = RequiredChannel.Any) {
    addInterceptUrl(matcher, SecurityConfig.createList(access), channel)
  }

  override def accessDecisionVoters = new WebExpressionVoter :: super.accessDecisionVoters
}

private[sec] trait LoginPage extends StatelessFilterChain {
  val loginPage: String = null

  override def entryPoint : AuthenticationEntryPoint = {
    val ep = new LoginUrlAuthenticationEntryPoint
    assert(loginPage != null, "You need to set the loginPage value or add the LoginPageGenerator trait")
    ep.setLoginFormUrl(loginPage)
    ep
  }
}

trait LoginPageGenerator extends StatelessFilterChain with LoginPage {
  override val loginPage = "/spring_security_login"

  override lazy val loginPageFilter = {
    new DefaultLoginPageGeneratingFilter(formLoginFilter.asInstanceOf[UsernamePasswordAuthenticationFilter],
      openIDFilter.asInstanceOf[AbstractAuthenticationProcessingFilter])
  }
}

trait FormLogin extends StatelessFilterChain with LoginPage {
  override lazy val formLoginFilter = {
    val filter = new UsernamePasswordAuthenticationFilter
    filter.setAuthenticationManager(internalAuthenticationManager)
    filter.setRememberMeServices(rememberMeServices)
    filter
  }
}

trait OpenID extends StatelessFilterChain with LoginPage with UserService {
  override lazy val openIDFilter = new OpenIDAuthenticationFilter
  lazy val openIDProvider = {
    val provider = new OpenIDAuthenticationProvider

    provider.setUserDetailsService(userDetailsService)
    provider
  }

  override def authenticationProviders = {
    openIDProvider :: super.authenticationProviders
  }
}

trait BasicAuthentication extends StatelessFilterChain {
  val basicAuthenticationEntryPoint = new BasicAuthenticationEntryPoint()

  override lazy val basicAuthenticationFilter = {
    val baf = new BasicAuthenticationFilter()
    baf.setAuthenticationManager(authenticationManager)
    baf.setAuthenticationEntryPoint(basicAuthenticationEntryPoint)
    baf
  }

  override def entryPoint : AuthenticationEntryPoint = basicAuthenticationEntryPoint
}

/**
 * Provides a UserDetailsService reference to services which require it
 */
trait UserService {
  val userDetailsService: UserDetailsService
}

