package sec

import org.scalatest.FlatSpec
import org.scalatest.matchers.ShouldMatchers

import Conversions._
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.access.SecurityConfig

trait AllowAllAuthentication extends StatelessFilterChain {
  override val authenticationManager = new AllowAllAuthenticationManager("ROLE_USER")
}

/**
 *
 * @author Luke Taylor
 */
class FilterChainSpec extends FlatSpec with ShouldMatchers with TestConversions {
  val filterChainWithForm = new FilterChain with FormLogin with LoginPageGenerator with AllowAllAuthentication
  val filterChainWithBasic = new FilterChain with BasicAuthentication with AllowAllAuthentication
  val filterChainWithBasicForm = new FilterChain with BasicAuthentication with FormLogin with LoginPageGenerator with AllowAllAuthentication
  val filterChainWithFormBasic = new FilterChain with FormLogin with BasicAuthentication with AllowAllAuthentication

  "A FilterChain" should "support adding of intercept URLs to security interceptor" in {
    val chain = new FilterChain with AllowAllAuthentication

    chain.addInterceptUrl(matcher = "/AAA", access = "AAA")
    chain.addInterceptUrl("/**", "BBB")
    // ** should overwrite /**
    chain.addInterceptUrl("**", "CCC")
    chain.addInterceptUrl("/toolate", "XXX")

    chain.filters

    val mds = chain.filterSecurityInterceptor.getSecurityMetadataSource match {
      case d : DefaultFilterInvocationSecurityMetadataSource => d
      case a : Any => fail("Expected DefaultFilterInvocationSecurityMetadataSource but was" + a)
    }

    mds.getAllConfigAttributes.size() should be (3)
    // /toolate comes after the wildcard so should be ignored
    assert(mds.getAttributes(stringToFilterInvocation("/toolate")).contains(new SecurityConfig("CCC")))
  }

  "A FilterChain with FormLogin" should "have a LoginUrlAuthenticationEntryPoint" in {
    assert(filterChainWithForm.entryPoint.isInstanceOf[LoginUrlAuthenticationEntryPoint])
  }

  it should "have 8 filters" in {
    filterChainWithForm.filters.length should be (8)
  }

  "A FilterChain with BasicAuthentication with FormLogin " should "have a LoginUrlAuthenticationEntryPoint" in {
    assert(filterChainWithBasicForm.entryPoint.isInstanceOf[LoginUrlAuthenticationEntryPoint])
  }

  "A FilterChain with FormLogin with BasicAuthentication" should "have a BasicAuthenticationEntryPoint" in {
    filterChainWithFormBasic.entryPoint should be theSameInstanceAs (filterChainWithFormBasic.basicAuthenticationEntryPoint)
  }
  it should "have 8 filters" in {
    filterChainWithFormBasic.filters.length should be (8)
  }

  "A FilterChain with ELAccessControl" should "have an Expression SecurityMDS" in {
    val chain = new FilterChain with FormLogin with LoginPageGenerator with ELAccessControl with AllowAllAuthentication

    chain.addInterceptUrl(matcher = "/AAA", access = "permitAll")
    chain.addInterceptUrl("/**", "hasAnyRole('a','b','c')")

    chain.filters

    val mds = chain.filterSecurityInterceptor.getSecurityMetadataSource match {
      case d : ExpressionBasedFilterInvocationSecurityMetadataSource => d
      case a : Any => fail("Expected ExpressionBasedFilterInvocationSecurityMetadataSource but was: " + a)
    }

    mds.getAllConfigAttributes.size() should be (2)
  }


}
