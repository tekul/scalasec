package sec

import org.scalatest.FlatSpec
import org.scalatest.matchers.ShouldMatchers

import Conversions._
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource
import org.springframework.security.access.SecurityConfig

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

  "A FilterChain with ELAccessControl" should "have an Expression SecurityMDS" in {
    val chain = new FilterChain with BasicAuthentication with ELAccessControl with AllowAllAuthentication {
      interceptUrl(matcher = "/AAA", access = "permitAll")
      interceptUrl("/**", "hasAnyRole('a','b','c')")
    }

    chain.filters

    val mds = chain.filterSecurityInterceptor.getSecurityMetadataSource match {
      case d : ExpressionBasedFilterInvocationSecurityMetadataSource => d
      case a : Any => fail("Expected ExpressionBasedFilterInvocationSecurityMetadataSource but was: " + a)
    }

    mds.getAllConfigAttributes.size() should be (2)
  }


}
