// Web push: VAPID signatures and push-message encryption.
import webpush from 'web-push';

webpush.setVapidDetails('mailto:ops@example.org', process.env.VAPID_PUBLIC, process.env.VAPID_PRIVATE);

export async function notify(subscription, payload) {
  return webpush.sendNotification(subscription, payload);
}
