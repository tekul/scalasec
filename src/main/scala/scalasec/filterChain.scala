package scalasec

import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter

import javax.servlet.Filter
import javax.servlet.http.HttpServletRequest

import java.util.Arrays
import java.lang.AssertionError
import org.springframework.security.web.session.SessionManagementFilter
import org.springframework.security.web.context.{SecurityContextRepository, NullSecurityContextRepository, HttpSessionSecurityContextRepository, SecurityContextPersistenceFilter}
import org.springframework.security.web.savedrequest.{RequestCache, HttpSessionRequestCache, NullRequestCache, RequestCacheAwareFilter}
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.authentication._
import org.springframework.security.web.authentication.session._
import org.springframework.security.web.{SecurityFilterChain, AuthenticationEntryPoint}
import org.springframework.security.web.util.RequestMatcher

import FilterPositions._

/**
 *
 */
abstract class FilterChain extends StatelessFilterChain with AnonymousAuthentication {
  override val securityContextRepository: SecurityContextRepository = new HttpSessionSecurityContextRepository

  override val requestCache: RequestCache = new HttpSessionRequestCache

  override val sessionAuthenticationStrategy: SessionAuthenticationStrategy = new SessionFixationProtectionStrategy

  lazy val requestCacheFilter = new RequestCacheAwareFilter(requestCache)

  lazy val sessionManagementFilter : Filter = new SessionManagementFilter(securityContextRepository, sessionAuthenticationStrategy)

  override def filtersInternal = (REQUEST_CACHE_FILTER, requestCacheFilter) ::
      (SESSION_MANAGEMENT_FILTER, sessionManagementFilter) :: super.filtersInternal
}

/**
 * @author Luke Taylor
 */
abstract class StatelessFilterChain extends Conversions with WebAccessControl with SecurityFilterChain {
  // Controls which requests will be handled by this filter chain
  val requestMatcher : RequestMatcher = "/**"

  // Services which are shared between filters
  val requestCache: RequestCache = new NullRequestCache
  val securityContextRepository: SecurityContextRepository = new NullSecurityContextRepository
  lazy val rememberMeServices: RememberMeServices = new NullRememberMeServices
  val sessionAuthenticationStrategy: SessionAuthenticationStrategy = new NullAuthenticatedSessionStrategy

  lazy val securityContextPersistenceFilter = new SecurityContextPersistenceFilter(securityContextRepository)

  val servletApiFilter = new SecurityContextHolderAwareRequestFilter()

  lazy val exceptionTranslationFilter = new ExceptionTranslationFilter(entryPoint, requestCache);

  def entryPoint : AuthenticationEntryPoint = new Http403ForbiddenEntryPoint

  /**
   * Returns the filters provided by this class along with their index in the filter chain for sorting
   */
  def filtersInternal: List[Tuple2[FilterPositions.Value,Filter]] =
      (SECURITY_CONTEXT_FILTER, securityContextPersistenceFilter) :: (SERVLET_API_SUPPORT_FILTER, servletApiFilter) ::
      (EXCEPTION_TRANSLATION_FILTER, exceptionTranslationFilter) :: (FILTER_SECURITY_INTERCEPTOR, filterSecurityInterceptor) :: Nil

  def filters: List[Filter] =
    for {
      pair <- filtersInternal sortWith comparePositions
    } yield pair._2

  // Implementation of SecurityFilterChain for direct use as a Spring Security bean
  private lazy val scFilters = Arrays.asList(filters:_*)

  final def getFilters = scFilters

  final def matches(request: HttpServletRequest) = requestMatcher.matches(request)
}

/**
 * Trait which assists with inserting custom filters before or after existing filters in the chain.
 */
trait InsertionHelper {
  def insertBefore(position: Class[_], filter: Filter, target: List[Filter]): List[Filter] = insert(position, filter, target, true)
  def insertAfter(position: Class[_], filter: Filter, target: List[Filter]): List[Filter] = insert(position, filter, target, false)

  private def insert(position: Class[_], filter: Filter, target: List[Filter], before: Boolean): List[Filter] =
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

