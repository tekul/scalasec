package sec

import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource
import org.scalatest.FlatSpec
import org.scalatest.matchers.ShouldMatchers

/**
 * @author Luke Taylor
 */

class ELAccessControlSpec extends FlatSpec with ShouldMatchers {

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
