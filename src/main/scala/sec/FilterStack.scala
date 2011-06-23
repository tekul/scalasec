package sec

import javax.servlet._
import java.lang.UnsupportedOperationException

/**
 * Abstract representation of the complete, ordered Spring Security filter stack without any filters
 *
 * @author Luke Taylor
 */
private[sec] abstract class FilterStack {
  private final val NO_FILTER = new Filter {
    def destroy() {throw new UnsupportedOperationException()}
    def doFilter(request: ServletRequest, response: ServletResponse, chain: javax.servlet.FilterChain) {throw new UnsupportedOperationException()}
    def init(filterConfig: FilterConfig) {throw new UnsupportedOperationException()}
  }

  def channelFilter : Filter = NO_FILTER
  def securityContextPersistenceFilter: Filter = NO_FILTER
  def logoutFilter: Filter = NO_FILTER
  def x509Filter: Filter  = NO_FILTER
  def formLoginFilter: Filter  = NO_FILTER
  def loginPageFilter: Filter  = NO_FILTER
  def basicAuthenticationFilter: Filter  = NO_FILTER
  def requestCacheFilter: Filter  = NO_FILTER
  def servletApiFilter: Filter  = NO_FILTER
  def rememberMeFilter: Filter  = NO_FILTER
  def anonymousFilter: Filter  = NO_FILTER
  def sessionManagementFilter: Filter  = NO_FILTER
  def exceptionTranslationFilter: Filter  = NO_FILTER
  def filterSecurityInterceptor: Filter  = NO_FILTER

  def filters : List[Filter] = {
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
