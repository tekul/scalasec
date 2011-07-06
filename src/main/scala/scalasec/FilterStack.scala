package scalasec

import javax.servlet._

/**
 * Abstract representation of the complete, ordered Spring Security filter stack without any filters
 *
 * @author Luke Taylor
 */
private[scalasec] abstract class FilterStack {
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
  val servletApiFilter: Filter = NO_FILTER
  lazy val rememberMeFilter: Filter = NO_FILTER
  lazy val anonymousFilter: Filter = NO_FILTER
  lazy val sessionManagementFilter: Filter = NO_FILTER
  val exceptionTranslationFilter: Filter
  val filterSecurityInterceptor: Filter

  /**
   * Assembles the list of filters in the correct order, filtering out any which have not been set by adding in the
   * appropriate trait.
   */
  def filters : List[Filter] = {
    val list : List[Filter] = List(securityContextPersistenceFilter,
      logoutFilter,
      x509Filter,
      formLoginFilter,
      openIDFilter,
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
