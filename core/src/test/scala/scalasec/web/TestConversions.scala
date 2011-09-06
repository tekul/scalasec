package scalasec.web

import org.springframework.security.web.FilterInvocation

trait TestConversions {
  implicit def stringToFilterInvocation(url: String) = new FilterInvocation(url, "GET")
}
