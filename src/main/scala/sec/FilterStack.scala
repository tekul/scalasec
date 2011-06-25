package sec

import javax.servlet._
import java.lang.UnsupportedOperationException

/**
 * Abstract representation of the complete, ordered Spring Security filter stack without any filters
 *
 * @author Luke Taylor
 */
private[sec] abstract class FilterStack {
  private final val NO_FILTER = null

  lazy val channelFilter : Filter = NO_FILTER
  val securityContextPersistenceFilter: Filter
  lazy val logoutFilter: Filter = NO_FILTER
  lazy val x509Filter: Filter = NO_FILTER
  lazy val formLoginFilter: Filter  = NO_FILTER
  lazy val openIDFilter: Filter = NO_FILTER
  lazy val loginPageFilter: Filter = NO_FILTER
  lazy val basicAuthenticationFilter: Filter = NO_FILTER
  lazy val requestCacheFilter: Filter = NO_FILTER
  lazy val servletApiFilter: Filter = NO_FILTER
  lazy val rememberMeFilter: Filter = NO_FILTER
  lazy val anonymousFilter: Filter = NO_FILTER
  lazy val sessionManagementFilter: Filter = NO_FILTER
  val exceptionTranslationFilter: Filter
  val filterSecurityInterceptor: Filter

  lazy val filters : List[Filter] = {
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

    list.filter(f => f ne NO_FILTER)
  }
}
