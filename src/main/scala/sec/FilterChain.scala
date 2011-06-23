package sec

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
import org.springframework.security.core.userdetails.memory.UserAttribute
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import java.util.Arrays
import org.springframework.security.access.{AccessDecisionManager, AccessDecisionVoter, SecurityConfig, ConfigAttribute}
import org.springframework.security.access.vote.{AffirmativeBased, AuthenticatedVoter, RoleVoter}
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.authentication.{AuthenticationManager, ProviderManager, AnonymousAuthenticationProvider, AuthenticationProvider}

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

  implicit def filterChainAsSecurityFilterChain(chain: BaseFilterChain): SecurityFilterChain = {
    new SecurityFilterChain(chain.requestMatcher, chain.filters: _*)
  }

  implicit def stringToGrantedAuthority(authority: String): GrantedAuthority = {
    new SimpleGrantedAuthority(authority)
  }

  implicit def stringToGrantedAuthorityList(authority: String) : ju.List[GrantedAuthority] = {
    Arrays.asList(new SimpleGrantedAuthority(authority))
  }
}

object Conversions extends Conversions


abstract class FilterChain extends BaseFilterChain {
  override val securityContextPersistenceFilter = new SecurityContextPersistenceFilter
}


/**
 * Todo. Add constructor injection to filters in spring sec (Anon, Fsi etc).
 *
 * @author Luke Taylor
 */
private[sec] abstract class BaseFilterChain extends AnyRef with Conversions {
  private final val emptySlot = new DelegatingFilterProxy

  val requestMatcher : RequestMatcher = "/**"
  val channelFilter = emptySlot
  val securityContextPersistenceFilter = new SecurityContextPersistenceFilter
  val logoutFilter : Filter = emptySlot
  val x509Filter : Filter = emptySlot
  val formLoginFilter : Filter = emptySlot
  val loginPageFilter : Filter = emptySlot
  def basicAuthenticationFilter : Filter = emptySlot
  val requestCacheFilter = new RequestCacheAwareFilter()
  val servletApiFilter = new SecurityContextHolderAwareRequestFilter()
  def rememberMeFilter = emptySlot
  def anonymousFilter : Filter = emptySlot

  def sessionManagementFilter : Filter = {
    new SessionManagementFilter(securityContextRepository)
  }

  def exceptionTranslationFilter = {
    val etf = new ExceptionTranslationFilter
    etf.setAuthenticationEntryPoint(entryPoint)
    etf
  }

  def filterSecurityInterceptor = {
    val fsi = new FilterSecurityInterceptor()
    fsi.setSecurityMetadataSource(securityMetadataSource)
    fsi.setAccessDecisionManager(accessDecisionManager)
    fsi
  }

  val securityContextRepository = new HttpSessionSecurityContextRepository

  def accessDecisionVoters : List[AccessDecisionVoter[_]] = List(new RoleVoter(), new AuthenticatedVoter())

  def accessDecisionManager : AccessDecisionManager = {
    val adm = new AffirmativeBased
    adm.setDecisionVoters(Arrays.asList(accessDecisionVoters: _*))
    adm
  }

  private[sec] def authenticationProviders : List[AuthenticationProvider] = Nil

  private[sec] def internalAuthenticationManager : ProviderManager = {
    val am = new ProviderManager
    am.setParent(authenticationManager)
    am.setProviders(Arrays.asList(authenticationProviders:_*))
    am
  }

  private var channels : ListMap[RequestMatcher, RequiredChannel.Value] = ListMap()
  private[sec] var accessUrls : ListMap[RequestMatcher, ju.List[ConfigAttribute]] = ListMap()

  private[sec] def securityMetadataSource : FilterInvocationSecurityMetadataSource
          = new DefaultFilterInvocationSecurityMetadataSource(accessUrls)


  def filters : List[Filter] = {
    securityContextPersistenceFilter.setSecurityContextRepository(securityContextRepository)

    val list : List[Filter] = List(securityContextPersistenceFilter,
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

  def authenticationManager : AuthenticationManager

  def addInterceptUrl(matcher : RequestMatcher, access : String, channel : RequiredChannel.Value = RequiredChannel.Any) {
    accessUrls = accessUrls + (matcher -> createConfigAttributes(access))
    channels = channels + (matcher -> channel)
  }

  private[sec] def createConfigAttributes(access : String) : ju.List[ConfigAttribute] = {
    SecurityConfig.createList(access.split(",") : _*);
  }
}

trait AnonymousAuthentication extends BaseFilterChain {
  val key = "replaceMeWithAProperKey"
  def provider = {
    val p = new AnonymousAuthenticationProvider
    p.setKey(key)
    p
  }
  val user = {
    val attribute = new UserAttribute()
    attribute.setPassword("anonymous")
    attribute.setAuthorities("ROLE_ANONYMOUS")
    attribute
  }

  override def authenticationProviders = {
    provider :: super.authenticationProviders
  }

  override def anonymousFilter = {
    val filter = new AnonymousAuthenticationFilter
    filter.setKey(key)
    filter.setUserAttribute(user)

    filter
  }
}

trait Logout extends BaseFilterChain {
  val logoutHandlers = List[LogoutHandler](new SecurityContextLogoutHandler())
  val logoutSuccessHandler : LogoutSuccessHandler = new SimpleUrlLogoutSuccessHandler()
  override val logoutFilter = new LogoutFilter(logoutSuccessHandler, logoutHandlers : _*)
}

trait ELConfiguration extends BaseFilterChain {
  val expressionHandler = new DefaultWebSecurityExpressionHandler()

  override lazy val securityMetadataSource = new ExpressionBasedFilterInvocationSecurityMetadataSource(accessUrls, expressionHandler)

  override def createConfigAttributes(access : String) : ju.List[ConfigAttribute] = {
    SecurityConfig.createList(access);
  }
}

trait FormLogin extends BaseFilterChain {
  override val formLoginFilter = new UsernamePasswordAuthenticationFilter()
  val formLoginEntryPoint = new LoginUrlAuthenticationEntryPoint()

  def loginPage(url : String) {
    formLoginEntryPoint.setLoginFormUrl(url)
  }

  override def entryPoint : AuthenticationEntryPoint = formLoginEntryPoint
}

trait BasicAuthentication extends BaseFilterChain {
  val basicAuthenticationEntryPoint = new BasicAuthenticationEntryPoint()

  override def basicAuthenticationFilter = {
    val baf = new BasicAuthenticationFilter()
    baf.setAuthenticationManager(authenticationManager)
    baf.setAuthenticationEntryPoint(basicAuthenticationEntryPoint)
    baf
  }


  override def entryPoint : AuthenticationEntryPoint = basicAuthenticationEntryPoint
}
