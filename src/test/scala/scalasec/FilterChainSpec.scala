package scalasec

import org.mockito.Mockito._
import org.scalatest.FlatSpec
import org.scalatest.matchers.ShouldMatchers

import Conversions._
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource
import org.springframework.security.access.SecurityConfig
import org.scalatest.mock.MockitoSugar
import org.springframework.security.web.savedrequest.RequestCache
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy

trait AllowAllAuthentication extends StatelessFilterChain {
  override val authenticationManager = new AllowAllAuthenticationManager("ROLE_USER")
}

/**
 *
 * @author Luke Taylor
 */
class FilterChainSpec extends FlatSpec with ShouldMatchers with TestConversions with MockitoSugar  {
  "A FilterChain" should "allow the use of a custom RequestCache" in {
    val rc = mock[RequestCache]
    new FilterChain with AllowAllAuthentication {
      override val requestCache = rc
    }
  }
  it should "allow the use of a custom SessionAuthenticationStrategy" in {
    val sas = mock[SessionAuthenticationStrategy]
    new FilterChain with AllowAllAuthentication {
      override val sessionAuthenticationStrategy = sas
    }
  }
  it should "support adding of intercept URLs to the security interceptor" in {
    val chain = new FilterChain with AllowAllAuthentication {
      interceptUrl(matcher = "/AAA", access = "AAA")
      interceptUrl("/**", "BBB")
    }

    chain.filters

    val mds = chain.filterSecurityInterceptor.getSecurityMetadataSource match {
      case d : DefaultFilterInvocationSecurityMetadataSource => d
      case a : Any => fail("Expected DefaultFilterInvocationSecurityMetadataSource but was" + a)
    }

    mds.getAllConfigAttributes.size() should be (2)
    assert(mds.getAttributes(stringToFilterInvocation("/AAA")).contains(new SecurityConfig("AAA")))
    assert(mds.getAttributes(stringToFilterInvocation("/XXX")).contains(new SecurityConfig("BBB")))
  }
  it should "not allow duplicate interceptUrl patterns" in {
    intercept[AssertionError] {
      new FilterChain with AllowAllAuthentication {
        interceptUrl(matcher = "/**", access = "AAA")
        interceptUrl("**", "BBB")
      }
    }

    intercept[AssertionError] {
      new FilterChain with AllowAllAuthentication {
        interceptUrl(matcher = "/aaa", access = "AAA")
        interceptUrl("/aaa", "BBB")
      }
    }
  }
  it should "not allow additional interceptUrls after a universal match" in {
    intercept[AssertionError] {
      new FilterChain with AllowAllAuthentication {
        interceptUrl("/aaa", "AAA")
        interceptUrl("/**", "XXX")
        interceptUrl("/bbb", "BBB")
      }
    }
  }
}
