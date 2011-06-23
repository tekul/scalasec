package sec

import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.authentication.www.{BasicAuthenticationEntryPoint, BasicAuthenticationFilter}
import org.springframework.security.web.util.RequestMatcher
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter
import org.springframework.security.web.access.expression.{DefaultWebSecurityExpressionHandler, ExpressionBasedFilterInvocationSecurityMetadataSource}
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
import org.springframework.security.web.authentication.{Http403ForbiddenEntryPoint, AnonymousAuthenticationFilter, LoginUrlAuthenticationEntryPoint, UsernamePasswordAuthenticationFilter}
import org.springframework.security.web.context.{SecurityContextRepository, NullSecurityContextRepository, HttpSessionSecurityContextRepository, SecurityContextPersistenceFilter}

object RequiredChannel extends Enumeration {
  val Http, Https, Any = Value
}

abstract class FilterChain extends StatelessFilterChain {
  override val securityContextRepository = new HttpSessionSecurityContextRepository
  override val requestCacheFilter = new RequestCacheAwareFilter()

  override def sessionManagementFilter : Filter = {
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

  override def securityContextPersistenceFilter = {
    val scpi = new SecurityContextPersistenceFilter
    scpi.setSecurityContextRepository(securityContextRepository)
    scpi
  }

  val securityContextRepository : SecurityContextRepository = new NullSecurityContextRepository

  override val servletApiFilter = new SecurityContextHolderAwareRequestFilter()

  override def exceptionTranslationFilter = {
    val etf = new ExceptionTranslationFilter
    etf.setAuthenticationEntryPoint(entryPoint)
    etf
  }

  def entryPoint : AuthenticationEntryPoint = new Http403ForbiddenEntryPoint

  override def filterSecurityInterceptor = {
    val fsi = new FilterSecurityInterceptor()
    fsi.setSecurityMetadataSource(securityMetadataSource)
    fsi.setAccessDecisionManager(accessDecisionManager)
    fsi
  }

  private[sec] var accessUrls : ListMap[RequestMatcher, ju.List[ConfigAttribute]] = ListMap()
  private[sec] def securityMetadataSource : FilterInvocationSecurityMetadataSource
          = new DefaultFilterInvocationSecurityMetadataSource(accessUrls)


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


  def authenticationManager : AuthenticationManager

  def addInterceptUrl(matcher : RequestMatcher, access : String, channel : RequiredChannel.Value = RequiredChannel.Any) {
    accessUrls = accessUrls + (matcher -> createConfigAttributes(access))
    channels = channels + (matcher -> channel)
  }

  private[sec] def createConfigAttributes(access : String) : ju.List[ConfigAttribute] = {
    SecurityConfig.createList(access.split(",") : _*);
  }
}

trait AnonymousAuthentication extends StatelessFilterChain {
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

trait Logout extends StatelessFilterChain {
  val logoutHandlers = List[LogoutHandler](new SecurityContextLogoutHandler())
  val logoutSuccessHandler : LogoutSuccessHandler = new SimpleUrlLogoutSuccessHandler()
  override val logoutFilter = new LogoutFilter(logoutSuccessHandler, logoutHandlers : _*)
}

trait ELConfiguration extends StatelessFilterChain {
  val expressionHandler = new DefaultWebSecurityExpressionHandler()

  override lazy val securityMetadataSource = new ExpressionBasedFilterInvocationSecurityMetadataSource(accessUrls, expressionHandler)

  override def createConfigAttributes(access : String) : ju.List[ConfigAttribute] = {
    SecurityConfig.createList(access);
  }
}

trait FormLogin extends StatelessFilterChain {
  override val formLoginFilter = new UsernamePasswordAuthenticationFilter()
  val formLoginEntryPoint = new LoginUrlAuthenticationEntryPoint()

  def loginPage(url : String) {
    formLoginEntryPoint.setLoginFormUrl(url)
  }

  override def entryPoint : AuthenticationEntryPoint = formLoginEntryPoint
}

trait BasicAuthentication extends StatelessFilterChain {
  val basicAuthenticationEntryPoint = new BasicAuthenticationEntryPoint()

  override def basicAuthenticationFilter = {
    val baf = new BasicAuthenticationFilter()
    baf.setAuthenticationManager(authenticationManager)
    baf.setAuthenticationEntryPoint(basicAuthenticationEntryPoint)
    baf
  }

  override def entryPoint : AuthenticationEntryPoint = basicAuthenticationEntryPoint
}
