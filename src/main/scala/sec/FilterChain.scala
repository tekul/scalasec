package sec

import org.springframework.security.access.{SecurityConfig, ConfigAttribute}
import org.springframework.security.web.{SecurityFilterChain, AuthenticationEntryPoint}
import org.springframework.security.web.authentication.www.{BasicAuthenticationEntryPoint, BasicAuthenticationFilter}
import org.springframework.security.web.util.{AnyRequestMatcher, AntPathRequestMatcher, RequestMatcher}
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter
import org.springframework.security.web.access.channel.ChannelProcessingFilter
import org.springframework.security.web.access.expression.{DefaultWebSecurityExpressionHandler, ExpressionBasedFilterInvocationSecurityMetadataSource}
import org.springframework.security.web.access.intercept.{DefaultFilterInvocationSecurityMetadataSource, FilterInvocationSecurityMetadataSource, FilterSecurityInterceptor}
import org.springframework.security.web.authentication.logout._
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
import org.springframework.web.filter.DelegatingFilterProxy
import org.springframework.security.web.authentication.{AnonymousAuthenticationFilter, LoginUrlAuthenticationEntryPoint, UsernamePasswordAuthenticationFilter}

import collection.immutable.ListMap

import javax.servlet.Filter

import java.{util => ju}
import org.springframework.security.web.session.SessionManagementFilter
import org.springframework.security.web.context.{HttpSessionSecurityContextRepository, SecurityContextPersistenceFilter}

object RequiredChannel extends Enumeration {
  val Http, Https, Any = Value
}

trait Conversions {
  implicit def stringToRequestMatcher(pattern: String) = pattern match {
    case "**" | "/**" => new AnyRequestMatcher()
    case _  => new AntPathRequestMatcher(pattern)
  }

  implicit def listMapAsJavaLinkedHashMap[A, B](m : ListMap[A, B]): ju.LinkedHashMap[A, B] = {
    val result = new ju.LinkedHashMap[A,B]
    m foreach { case (key, value) => result.put(key, value)}
    result
  }

  implicit def filterChainAsSecurityFilterChain(chain: FilterChain): SecurityFilterChain = {
    new SecurityFilterChain(chain.requestMatcher, chain.filters: _*)
  }
}

object Conversions extends Conversions

/*
    CHANNEL_FILTER,
    CONCURRENT_SESSION_FILTER,
    SECURITY_CONTEXT_FILTER,
    LOGOUT_FILTER,
    X509_FILTER,
    PRE_AUTH_FILTER,
    CAS_FILTER,
    FORM_LOGIN_FILTER,
    OPENID_FILTER,
    LOGIN_PAGE_FILTER,
    DIGEST_AUTH_FILTER,
    BASIC_AUTH_FILTER,
    REQUEST_CACHE_FILTER,
    SERVLET_API_SUPPORT_FILTER,
    JAAS_API_SUPPORT_FILTER,
    REMEMBER_ME_FILTER,
    ANONYMOUS_FILTER,
    SESSION_MANAGEMENT_FILTER,
    EXCEPTION_TRANSLATION_FILTER,
    FILTER_SECURITY_INTERCEPTOR,
    SWITCH_USER_FILTER,

 */

/**
 *
 * @author Luke Taylor
 */
trait FilterChain extends Conversions {
  private final val emptySlot = new DelegatingFilterProxy

  val requestMatcher : RequestMatcher = "/**"
  val channelFilter = new ChannelProcessingFilter()
  val securityContextPersistenceFilter = new SecurityContextPersistenceFilter
  val logoutFilter : Filter = emptySlot
  val x509Filter : Filter = emptySlot
  val formLoginFilter : Filter = emptySlot
  val loginPageFilter : Filter = emptySlot
  val basicAuthenticationFilter : Filter = emptySlot
  val requestCacheFilter = new RequestCacheAwareFilter()
  val servletApiFilter = new SecurityContextHolderAwareRequestFilter()
  val rememberMeFilter = emptySlot
  val anonymousFilter = new AnonymousAuthenticationFilter

  def sessionManagementFilter : Filter = {
    new SessionManagementFilter(securityContextRepository)
  }
  val exceptionTranslationFilter = new SecurityContextPersistenceFilter()
  val filterSecurityInterceptor = new FilterSecurityInterceptor()

  val securityContextRepository = new HttpSessionSecurityContextRepository

  private var channels : ListMap[RequestMatcher, RequiredChannel.Value] = ListMap()
  private[sec] var accessUrls : ListMap[RequestMatcher, ju.List[ConfigAttribute]] = ListMap()

  private[sec] lazy val securityMetadataSource : FilterInvocationSecurityMetadataSource
          = new DefaultFilterInvocationSecurityMetadataSource(accessUrls)


  def filters : List[Filter] = {
    filterSecurityInterceptor.setSecurityMetadataSource(securityMetadataSource)
    securityContextPersistenceFilter.setSecurityContextRepository(securityContextRepository)

    var list : List[Filter] = List(securityContextPersistenceFilter,
      logoutFilter,
      x509Filter,
      formLoginFilter,
      loginPageFilter,
      basicAuthenticationFilter,
      requestCacheFilter,
      servletApiFilter,
      rememberMeFilter,
      anonymousFilter,
      sessionManagementFilter,
      exceptionTranslationFilter,
      filterSecurityInterceptor)

    list.filter(f => f ne emptySlot)
  }

  def entryPoint : AuthenticationEntryPoint

  def addInterceptUrl(matcher : RequestMatcher, access : String, channel : RequiredChannel.Value = RequiredChannel.Any) {
    accessUrls = accessUrls + (matcher -> createConfigAttributes(access))
    channels = channels + (matcher -> channel)
  }

  private[sec] def createConfigAttributes(access : String) : ju.List[ConfigAttribute] = {
    SecurityConfig.createList(access.split(",") : _*);
  }
}

trait Logout extends FilterChain {
  val logoutHandlers = List[LogoutHandler](new SecurityContextLogoutHandler())
  val logoutSuccessHandler : LogoutSuccessHandler = new SimpleUrlLogoutSuccessHandler()
  override val logoutFilter = new LogoutFilter(logoutSuccessHandler, logoutHandlers : _*)
}

trait ELConfiguration extends FilterChain {
  val expressionHandler = new DefaultWebSecurityExpressionHandler()

  override lazy val securityMetadataSource = new ExpressionBasedFilterInvocationSecurityMetadataSource(accessUrls, expressionHandler)

  override def createConfigAttributes(access : String) : ju.List[ConfigAttribute] = {
    SecurityConfig.createList(access);
  }
}

trait FormLogin extends FilterChain {
  override val formLoginFilter = new UsernamePasswordAuthenticationFilter()
  val formLoginEntryPoint = new LoginUrlAuthenticationEntryPoint()

  def loginPage(url : String) {
    formLoginEntryPoint.setLoginFormUrl(url)
  }

  override def entryPoint : AuthenticationEntryPoint = formLoginEntryPoint
}

trait BasicAuthentication extends FilterChain {
  override val basicAuthenticationFilter = new BasicAuthenticationFilter()
  val basicAuthenticationEntryPoint = new BasicAuthenticationEntryPoint()

  override def entryPoint : AuthenticationEntryPoint = basicAuthenticationEntryPoint
}
