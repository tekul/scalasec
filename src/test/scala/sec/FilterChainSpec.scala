package sec

import org.scalatest.FlatSpec
import org.scalatest.matchers.ShouldMatchers

import Conversions._
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource

trait AllowAllAuthentication extends StatelessFilterChain {
  override val authenticationManager = new AllowAllAuthenticationManager("ROLE_USER")
}
/**
 *
 * @author Luke Taylor
 */
class FilterChainSpec extends FlatSpec with ShouldMatchers {
  val filterChainWithForm = new FilterChain with FormLogin with AllowAllAuthentication
  val filterChainWithBasic = new FilterChain with BasicAuthentication with AllowAllAuthentication
  val filterChainWithBasicForm = new FilterChain with BasicAuthentication with FormLogin with AllowAllAuthentication
  val filterChainWithFormBasic = new FilterChain with FormLogin with BasicAuthentication with AllowAllAuthentication

  "A FilterChain" should "support adding of intercept URLs to security interceptor" in {
    val chain = new FilterChain with AllowAllAuthentication

    chain.addInterceptUrl(matcher = "/AAA", access = "AAA")
    chain.addInterceptUrl("/**", "BBB")
    chain.addInterceptUrl("**", "CCC")

    chain.filters

    val mds = chain.filterSecurityInterceptor.getSecurityMetadataSource match {
      case d : DefaultFilterInvocationSecurityMetadataSource => d
      case a : Any => fail("Expected DefaultFilterInvocationSecurityMetadataSource but was" + a)
    }

    mds.getAllConfigAttributes.size() should be (2)
  }

  "A FilterChain with FormLogin" should "have a LoginUrlAuthenticationEntryPoint" in {
    filterChainWithForm.entryPoint should be theSameInstanceAs (filterChainWithForm.formLoginEntryPoint)
  }

  it should "have 7 filters" in {
    filterChainWithForm.filters.length should be (7)
  }

  "A FilterChain with BasicAuthentication with FormLogin " should "have a LoginUrlAuthenticationEntryPoint" in {
    filterChainWithBasicForm.entryPoint should be theSameInstanceAs (filterChainWithBasicForm.formLoginEntryPoint)
  }

  "A FilterChain with FormLogin with BasicAuthentication" should "have a BasicAuthenticationEntryPoint" in {
    filterChainWithFormBasic.entryPoint should be theSameInstanceAs (filterChainWithFormBasic.basicAuthenticationEntryPoint)
  }
  it should "have 8 filters" in {
    filterChainWithFormBasic.filters.length should be (8)
  }

  "A FilterChain with ELConfiguration" should "have an Expression SecurityMDS" in {
    val chain = new FilterChain with FormLogin with ELConfiguration with AllowAllAuthentication

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
