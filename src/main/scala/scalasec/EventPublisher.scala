package scalasec

import org.springframework.context.{ApplicationEvent, ApplicationEventPublisher, ApplicationEventPublisherAware}

/**
 * Trait which allows non Spring Bean classes to make use of the application context's
 * `ApplicationEventPublisher`.
 */
private[scalasec] trait EventPublisher extends ApplicationEventPublisherAware {
  var delegate: Option[ApplicationEventPublisher] = None

  val eventPublisher = new ApplicationEventPublisher {
    def publishEvent(a: ApplicationEvent) {
      delegate match {
        case Some(p) => p.publishEvent(a)
        case None =>
      }
    }
  }

  def setApplicationEventPublisher(publisher: ApplicationEventPublisher) {
    delegate = Some(publisher)
  }
}
