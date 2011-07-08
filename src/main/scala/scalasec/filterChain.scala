package scalasec

import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter

import javax.servlet.Filter

import org.springframework.security.web.session.SessionManagementFilter
import java.util.Arrays
import org.springframework.security.web.context.{SecurityContextRepository, NullSecurityContextRepository, HttpSessionSecurityContextRepository, SecurityContextPersistenceFilter}
import org.springframework.security.web.savedrequest.{RequestCache, HttpSessionRequestCache, NullRequestCache, RequestCacheAwareFilter}
import javax.servlet.http.HttpServletRequest
import java.lang.AssertionError
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.authentication._
import org.springframework.security.web.authentication.session.{SessionAuthenticationStrategy, SessionFixationProtectionStrategy, NullAuthenticatedSessionStrategy}
import org.springframework.security.web.{SecurityFilterChain, AuthenticationEntryPoint}
import org.springframework.security.web.util.RequestMatcher

/**
 *
 */
abstract class FilterChain extends StatelessFilterChain with AnonymousAuthentication {
  override val securityContextRepository: SecurityContextRepository = new HttpSessionSecurityContextRepository

  override val requestCache: RequestCache = new HttpSessionRequestCache

  override val sessionAuthenticationStrategy: SessionAuthenticationStrategy = new SessionFixationProtectionStrategy

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
abstract class StatelessFilterChain extends FilterStack with Conversions with WebAccessControl with SecurityFilterChain {
  // Controls which requests will be handled by this filter chain
  val requestMatcher : RequestMatcher = "/**"

  // Services which are shared between filters
  val requestCache: RequestCache = new NullRequestCache
  val securityContextRepository: SecurityContextRepository = new NullSecurityContextRepository
  lazy val rememberMeServices: RememberMeServices = new NullRememberMeServices
  val sessionAuthenticationStrategy: SessionAuthenticationStrategy = new NullAuthenticatedSessionStrategy

  override lazy val securityContextPersistenceFilter = new SecurityContextPersistenceFilter(securityContextRepository)

  override val servletApiFilter = new SecurityContextHolderAwareRequestFilter()

  override lazy val exceptionTranslationFilter = new ExceptionTranslationFilter(entryPoint, requestCache);

  def entryPoint : AuthenticationEntryPoint = new Http403ForbiddenEntryPoint

  // Implementation of SecurityFilterChain for direct use as a Spring Security bean
  lazy val scFilters = Arrays.asList(filters:_*)

  final def getFilters = scFilters

  final def matches(request: HttpServletRequest) = requestMatcher.matches(request)
}

/**
 * Trait which assists with inserting custom filters before or after existing filters in the chain.
 */
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

