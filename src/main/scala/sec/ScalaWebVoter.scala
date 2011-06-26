package sec

import org.springframework.security.web.FilterInvocation
import org.springframework.security.access.{ConfigAttribute, AccessDecisionVoter}
import org.springframework.security.core.Authentication
import java.{util => ju}

import scala.collection.JavaConversions._

/**
 * @author Luke Taylor
 */
class ScalaWebVoter extends AccessDecisionVoter[FilterInvocation] {
  def vote(authentication: Authentication, secured : FilterInvocation, attributes: ju.Collection[ConfigAttribute]) = {
    attributes.find(_.isInstanceOf[ScalaWebConfigAttribute]) match {
      case Some(s) =>
        if (s.asInstanceOf[ScalaWebConfigAttribute].predicate.apply(authentication, secured.getHttpRequest))
          AccessDecisionVoter.ACCESS_GRANTED
        else
          AccessDecisionVoter.ACCESS_DENIED
      case None => AccessDecisionVoter.ACCESS_ABSTAIN
    }
  }

  def supports(clazz: Class[_]) = clazz.isAssignableFrom(classOf[FilterInvocation])

  def supports(attribute: ConfigAttribute) = attribute.isInstanceOf[ScalaWebConfigAttribute]
}
