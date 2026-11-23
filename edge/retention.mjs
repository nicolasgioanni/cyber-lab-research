// Bind the private D1 database as LAB_EVENTS and schedule "7 * * * *" (UTC).
// Disable workers.dev and preview URLs. This module exposes no HTTP handler.
export default {
  async scheduled(_event, env) {
    const db = env.LAB_EVENTS;
    const now = Math.floor(Date.now() / 1000);
    await db.batch([
      db.prepare('DELETE FROM access_events WHERE at<=?').bind(now - 7 * 86400),
      db.prepare('DELETE FROM admission_grants WHERE expires<=?').bind(now)
    ]);
  }
};
