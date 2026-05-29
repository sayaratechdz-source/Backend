'use strict';

module.exports = {
  register({ strapi }) {},

  bootstrap({ strapi }) {

    // ── اعتراض PUT /api/users/:id عبر middleware ────────────────────────────
    // الـ frontend يرسل هذا الطلب بـ token خاطئ — نعترضه قبل وصوله لـ Strapi
    strapi.server.use(async (ctx, next) => {
      const isPutUser = ctx.method === 'PUT' && /^\/api\/users\/\d+$/.test(ctx.path);
      if (!isPutUser) return next();

      const authHeader = ctx.request.headers['authorization'];
      if (!authHeader || !authHeader.startsWith('Bearer ')) return next();

      const token = authHeader.split(' ')[1];
      let decoded;
      try {
        decoded = await strapi.plugin('users-permissions').service('jwt').verify(token);
      } catch {
        return next(); // token غير صالح — اتركه لـ Strapi
      }

      const targetId = parseInt(ctx.path.split('/').pop(), 10);

      // المستخدم يعدّل نفسه فقط
      if (decoded.id !== targetId) return next();

      const body = ctx.request.body;
      const { vendeurStatus } = body || {};

      const allowedStatuses = ['pending', 'approved', 'rejected'];
      if (!vendeurStatus || !allowedStatuses.includes(vendeurStatus)) return next();

      try {
        const updated = await strapi.db.query('plugin::users-permissions.user').update({
          where: { id: targetId },
          data: { vendeurStatus },
          populate: { role: true },
        });

        ctx.status = 200;
        ctx.body = {
          id: updated.id,
          username: updated.username,
          email: updated.email,
          vendeurStatus: updated.vendeurStatus,
          role: updated.role
            ? { id: updated.role.id, name: updated.role.name, type: updated.role.type }
            : null,
        };
      } catch (e) {
        strapi.log.error('[middleware PUT /api/users/:id] Error:', e.message);
        return next();
      }
    });

    strapi.server.router.get("/api/admin/users", async (ctx) => {
      try {
        // ── 1. التحقق من وجود Authorization header ──────────
        const authHeader = ctx.request.headers['authorization'];
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          ctx.status = 401;
          ctx.body = { error: 'Unauthorized: missing token' };
          return;
        }

        const token = authHeader.split(' ')[1];

        // ── 2. التحقق من صحة الـ JWT ─────────────────────────
        let decoded;
        try {
          decoded = await strapi.plugin('users-permissions').service('jwt').verify(token);
        } catch {
          ctx.status = 401;
          ctx.body = { error: 'Unauthorized: invalid token' };
          return;
        }

        // ── 3. التحقق أن المستخدم admin أو superAdmin ────────
        const user = await strapi.db.query('plugin::users-permissions.user').findOne({
          where: { id: decoded.id },
          populate: { role: true },
        });

        if (!user || !user.role) {
          ctx.status = 403;
          ctx.body = { error: 'Forbidden: user not found' };
          return;
        }

        const allowedRoles = ['admin', 'superadmin', 'Administrator'];
        if (!allowedRoles.includes(user.role.type) && !allowedRoles.includes(user.role.name)) {
          ctx.status = 403;
          ctx.body = { error: 'Forbidden: insufficient permissions' };
          return;
        }

        // ── 4. جلب جميع المستخدمين ───────────────────────────
        const users = await strapi.db.query('plugin::users-permissions.user').findMany({
          populate: { role: true },
        });

        ctx.body = users.map(u => ({
          id: u.id,
          username: u.username,
          email: u.email,
          createdAt: u.createdAt,
          blocked: u.blocked,
          vendeurStatus: u.vendeurStatus || null,
          role: u.role,
        }));

      } catch (e) {
        ctx.status = 500;
        ctx.body = { error: e.message };
      }
    });
  },
};
