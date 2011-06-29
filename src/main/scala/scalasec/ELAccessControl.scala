package scalasec

import org.springframework.security.web.util.RequestMatcher
import org.springframework.security.access.SecurityConfig
import org.springframework.security.web.access.expression.{WebExpressionVoter, ExpressionBasedFilterInvocationSecurityMetadataSource, DefaultWebSecurityExpressionHandler}

/**
 * Trait which mixes in standard web access-control functionality.
 * But why use EL, when you can use Scala functions directly?
 *
 * @author Luke Taylor
 */
trait ELAccessControl extends StatelessFilterChain {
  val expressionHandler = new DefaultWebSecurityExpressionHandler()

  override lazy val securityMetadataSource = new ExpressionBasedFilterInvocationSecurityMetadataSource(accessUrls, expressionHandler)

  override def interceptUrl(matcher: RequestMatcher, access: String, channel: RequiredChannel.Value = RequiredChannel.Any) {
    addInterceptUrl(matcher, SecurityConfig.createList(access), channel)
  }

  override def accessDecisionVoters = new WebExpressionVoter :: super.accessDecisionVoters
}
