package scalasec

import org.springframework.security.web.authentication.www.{BasicAuthenticationEntryPoint, BasicAuthenticationFilter}
import org.springframework.security.web.access.intercept.{DefaultFilterInvocationSecurityMetadataSource, FilterInvocationSecurityMetadataSource, FilterSecurityInterceptor}
import org.springframework.security.web.authentication.logout._
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
import collection.immutable.ListMap

import javax.servlet.Filter

import java.{util => ju}
import org.springframework.security.web.session.SessionManagementFilter
import java.util.Arrays
import org.springframework.security.access.{AccessDecisionManager, AccessDecisionVoter, SecurityConfig, ConfigAttribute}
import org.springframework.security.access.vote.{AffirmativeBased, AuthenticatedVoter, RoleVoter}
import org.springframework.security.authentication.{AuthenticationManager, ProviderManager, AnonymousAuthenticationProvider, AuthenticationProvider}
import org.springframework.security.web.context.{SecurityContextRepository, NullSecurityContextRepository, HttpSessionSecurityContextRepository, SecurityContextPersistenceFilter}
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.savedrequest.{RequestCache, HttpSessionRequestCache, NullRequestCache, RequestCacheAwareFilter}
import javax.servlet.http.HttpServletRequest
import org.springframework.security.core.Authentication
import org.springframework.security.openid.{OpenID4JavaConsumer, OpenIDAuthenticationProvider, OpenIDAuthenticationFilter}
import java.lang.AssertionError
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.authentication._
import org.springframework.security.web.authentication.session.{SessionAuthenticationStrategy, SessionFixationProtectionStrategy, NullAuthenticatedSessionStrategy}
import org.springframework.security.web.{SecurityFilterChain, AuthenticationEntryPoint}
import org.springframework.security.web.util.{AnyRequestMatcher, RequestMatcher}
import org.springframework.context.annotation.Lazy

/**
 * Enum containing the options for secure channel
 */
object RequiredChannel extends Enumeration {
  val Http, Https, Any = Value
}

abstract class FilterChain extends StatelessFilterChain with AnonymousAuthentication {
  override val securityContextRepository: SecurityContextRepository = new HttpSessionSecurityContextRepository

  override lazy val requestCache: RequestCache = new HttpSessionRequestCache

  override lazy val sessionAuthenticationStrategy: SessionAuthenticationStrategy = new SessionFixationProtectionStrategy

  override lazy val requestCacheFilter = {
    new RequestCacheAwareFilter(requestCache)
  }

  override lazy val sessionManagementFilter : Filter = {
    new SessionManagementFilter(securityContextRepository, sessionAuthenticationStrategy)
  }
}

/**
 * @author Luke Taylor
 */
abstract class StatelessFilterChain extends FilterStack with Conversions with SecurityFilterChain {
  // Controls which requests will be handled by this filter chain
  val requestMatcher : RequestMatcher = "/**"

  override lazy val securityContextPersistenceFilter = {
    new SecurityContextPersistenceFilter(securityContextRepository)
  }

  val securityContextRepository: SecurityContextRepository = new NullSecurityContextRepository

  override lazy val servletApiFilter = new SecurityContextHolderAwareRequestFilter()

  lazy val requestCache: RequestCache = new NullRequestCache
  lazy val rememberMeServices: RememberMeServices = new NullRememberMeServices
  lazy val sessionAuthenticationStrategy: SessionAuthenticationStrategy = new NullAuthenticatedSessionStrategy

  override lazy val exceptionTranslationFilter = {
    new ExceptionTranslationFilter(entryPoint, requestCache);
  }

  def entryPoint : AuthenticationEntryPoint = new Http403ForbiddenEntryPoint

  override lazy val filterSecurityInterceptor = {
    val fsi = new FilterSecurityInterceptor()
    fsi.setSecurityMetadataSource(securityMetadataSource)
    fsi.setAccessDecisionManager(accessDecisionManager)
    fsi
  }

  private var channels : ListMap[RequestMatcher, RequiredChannel.Value] = ListMap()
  private[scalasec] var accessUrls : ListMap[RequestMatcher, ju.List[ConfigAttribute]] = ListMap()
  private[scalasec] def securityMetadataSource : FilterInvocationSecurityMetadataSource
          = new DefaultFilterInvocationSecurityMetadataSource(accessUrls)

  def interceptUrl(matcher: RequestMatcher, access: String, channel: RequiredChannel.Value = RequiredChannel.Any) {
    addInterceptUrl(matcher, SecurityConfig.createList(access.split(",") : _*), channel)
  }

  def interceptUrlScala(matcher: RequestMatcher, access: (Authentication, HttpServletRequest) => Boolean, channel: RequiredChannel.Value = RequiredChannel.Any) {
    addInterceptUrl(matcher, Arrays.asList(new ScalaWebConfigAttribute(access)), channel)
  }

  private[scalasec] def addInterceptUrl(matcher: RequestMatcher, attributes: ju.List[ConfigAttribute], channel: RequiredChannel.Value) {
    assert(!accessUrls.contains(matcher), "An identical RequestMatcher already exists: " + matcher)
    assert(!accessUrls.exists(_._1.isInstanceOf[AnyRequestMatcher]), "A universal match has already been included in the " +
      "list, so any further interceptUrls will have no effect")
    accessUrls = accessUrls + (matcher -> attributes)
    channels = channels + (matcher -> channel)
  }

  def accessDecisionVoters : List[AccessDecisionVoter[_]] = List(new RoleVoter(), new AuthenticatedVoter())

  lazy val accessDecisionManager : AccessDecisionManager = {
    new AffirmativeBased(Arrays.asList(accessDecisionVoters: _*))
  }

  private[scalasec] def authenticationProviders : List[AuthenticationProvider] = Nil

  private[scalasec] lazy val internalAuthenticationManager : ProviderManager = {
    new ProviderManager(Arrays.asList(authenticationProviders:_*), authenticationManager)
  }

  def authenticationManager : AuthenticationManager

  // Implementation of SecurityFilterChain for direct use as a Spring Security bean
  lazy val scFilters = Arrays.asList(filters:_*)

  final def getFilters = scFilters

  final def matches(request: HttpServletRequest) = requestMatcher.matches(request)
}

trait AnonymousAuthentication extends StatelessFilterChain {
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

trait FormLogin extends StatelessFilterChain with LoginPage {
  override lazy val formLoginFilter = {
    val filter = new UsernamePasswordAuthenticationFilter
    filter.setAuthenticationManager(authenticationManager)
    filter.setRememberMeServices(rememberMeServices)
    filter
  }
}

trait OpenID extends StatelessFilterChain with LoginPage with UserService {
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

trait BasicAuthentication extends StatelessFilterChain {
  val basicAuthenticationEntryPoint = new BasicAuthenticationEntryPoint()

  override lazy val basicAuthenticationFilter =
    new BasicAuthenticationFilter(authenticationManager, basicAuthenticationEntryPoint)

  override def entryPoint : AuthenticationEntryPoint = basicAuthenticationEntryPoint
}

trait InsertionHelper {
  def insertBefore(position: Class[_], filter: Filter, target: List[Filter]) : List[Filter] = {
    insert(position, filter, target, true)
  }
  def insertAfter(position: Class[_], filter: Filter, target: List[Filter]) : List[Filter] = {
    insert(position, filter, target, false)
  }

  private def insert(position: Class[_], filter: Filter, target: List[Filter], before: Boolean): List[Filter] = {
    target match {
      case f :: rest =>
        if (f.getClass == position) {
          if (before) {filter :: f :: rest} else {f :: filter :: rest}
        } else {
          f :: insert(position, filter, rest, before)
        }
      case _ => throw new AssertionError("Failed to find filter of type " + position + " in list")
    }
  }
}

/**
 * Provides a UserDetailsService reference to services which require it
 */
trait UserService {
  val userDetailsService: UserDetailsService
//  lazy val userDetailsService: UserDetailsService = {
//    throw new AssertionError("You need to set the userDetailsService")
//  }
}

