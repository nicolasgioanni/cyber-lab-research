import { DatabaseSync } from 'node:sqlite';

// Run the same SQL against SQLite, including a transaction spanning D1 batch statements.
export class Database {
  engine = new DatabaseSync(':memory:');
  prepare(sql) {
    const statement = (values = []) => ({
      bind: (...args) => statement(args),
      first: async () => this.engine.prepare(sql).get(...values) ?? null,
      run: async () => ({meta:{changes:this.engine.prepare(sql).run(...values).changes}}),
    });
    return statement();
  }
  // Keep transactions serial as D1 does for a primary SQLite connection.
  queue = Promise.resolve();
  batch(items) {
    const result = this.queue.then(() => this.transaction(items));
    this.queue = result.catch(() => {});
    return result;
  }
  async transaction(items) {
    this.engine.exec('BEGIN');
    try {
      const results = [];
      for (const item of items) results.push(await item.run());
      this.engine.exec('COMMIT');
      return results;
    } catch (error) {
      this.engine.exec('ROLLBACK'); throw error;
    }
  }
}
