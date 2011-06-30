package scalasec

import org.scalatest.FlatSpec
import org.scalatest.matchers.ShouldMatchers

import Conversions._
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource
import org.springframework.security.access.SecurityConfig
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter
import org.springframework.security.web.access.ExceptionTranslationFilter

trait AllowAllAuthentication extends StatelessFilterChain {
  override val authenticationManager = new AllowAllAuthenticationManager("ROLE_USER")
}

/**
 *
 * @author Luke Taylor
 */
class FilterChainSpec extends FlatSpec with ShouldMatchers with TestConversions {
  "A FilterChain" should "support adding of intercept URLs to security interceptor" in {
    val chain = new FilterChain with AllowAllAuthentication {
      interceptUrl(matcher = "/AAA", access = "AAA")
      interceptUrl("/**", "BBB")
      interceptUrl("/toolate", "XXX")
    }

    chain.filters

    val mds = chain.filterSecurityInterceptor.getSecurityMetadataSource match {
      case d : DefaultFilterInvocationSecurityMetadataSource => d
      case a : Any => fail("Expected DefaultFilterInvocationSecurityMetadataSource but was" + a)
    }

    mds.getAllConfigAttributes.size() should be (3)
    // /toolate comes after the wildcard so should be ignored
    assert(mds.getAttributes(stringToFilterInvocation("/toolate")).contains(new SecurityConfig("BBB")))
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
  it should "allow easy insertion of additional filters" in {
    val chain = new StatelessFilterChain with AllowAllAuthentication with InsertionHelper {
      override def filters = {
        insertAfter(classOf[ExceptionTranslationFilter], new X509AuthenticationFilter, super.filters)
      }
    }

    assert(chain.filters(3).isInstanceOf[X509AuthenticationFilter])

    val chain2 = new StatelessFilterChain with AllowAllAuthentication with InsertionHelper {
      override def filters = {
        insertBefore(classOf[ExceptionTranslationFilter], new X509AuthenticationFilter, super.filters)
      }
    }

    assert(chain2.filters(2).isInstanceOf[X509AuthenticationFilter])
  }
}
