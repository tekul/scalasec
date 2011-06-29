package scalasec

import org.springframework.security.web.FilterInvocation

/**
 * @author Luke Taylor
 */

trait TestConversions {
  implicit def stringToFilterInvocation(url: String) = new FilterInvocation(url, "GET")
}
