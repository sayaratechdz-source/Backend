'use strict';

const bcrypt = require('bcryptjs');

// ── مساعد: بناء كائن المستخدم للـ response ──────────────────────────────────
function buildUserResponse(user, role) {
  return {
    id:            user.id,
    username:      user.username,
    email:         user.email,
    confirmed:     user.confirmed,
    blocked:       user.blocked,
    vendeurStatus: user.vendeurStatus || null,
    role: role
      ? { id: role.id, name: role.name, type: role.type }
      : null,
  };
}

// ── مساعد: التحقق من صيغة الإيميل ──────────────────────────────────────────
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

module.exports = (plugin) => {

  const originalCallback = plugin.controllers.auth.callback;

  // ── التسجيل ─────────────────────────────────────────────────────────────
  plugin.controllers.auth.register = async (ctx) => {
    // في Strapi v4 extensions، strapi متاح كـ global أو عبر ctx.state
    const strapiInstance = strapi;

    try {
      const {
        username, email, password,
        isVendor,
        vendeurStatus,
        firstName, lastName, phone, birthDate, gender,
      } = ctx.request.body;

      // ── 1. التحقق من الحقول المطلوبة ──────────────────────
      if (!username || !email || !password) {
        ctx.status = 400;
        ctx.body = { error: { message: 'username و email و password مطلوبة' } };
        return;
      }

      if (!isValidEmail(email)) {
        ctx.status = 400;
        ctx.body = { error: { message: 'صيغة البريد الإلكتروني غير صحيحة' } };
        return;
      }

      if (password.length < 6) {
        ctx.status = 400;
        ctx.body = { error: { message: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' } };
        return;
      }

      if (username.length < 3) {
        ctx.status = 400;
        ctx.body = { error: { message: 'اسم المستخدم يجب أن يكون 3 أحرف على الأقل' } };
        return;
      }

      // ── 2. التحقق من عدم تكرار الإيميل أو اليوزرنيم ──────
      const existingUser = await strapiInstance.db
        .query('plugin::users-permissions.user')
        .findOne({
          where: { $or: [{ email: email.toLowerCase() }, { username }] },
        });

      if (existingUser) {
        ctx.status = 400;
        ctx.body = { error: { message: 'البريد الإلكتروني أو اسم المستخدم مستخدم بالفعل' } };
        return;
      }

      // ── 3. جلب الدور المناسب ──────────────────────────────
      // الـ frontend يرسل vendeurStatus: "pending" للـ vendeur
      // أو isVendor: true/"true" — ندعم الحالتين
      strapiInstance.log.info(`[register] isVendor raw value: ${JSON.stringify(isVendor)} | type: ${typeof isVendor}`);
      const isVendorBool = isVendor === true || isVendor === 'true' || vendeurStatus === 'pending';
      strapiInstance.log.info(`[register] isVendorBool: ${isVendorBool} | roleName: ${isVendorBool ? 'vendeur' : 'acheteur'}`);
      const roleName = isVendorBool ? 'vendeur' : 'acheteur';
      let assignedRole = await strapiInstance.db
        .query('plugin::users-permissions.role')
        .findOne({ where: { name: roleName } });

      if (!assignedRole) {
        strapiInstance.log.warn(`[register] Role "${roleName}" not found, falling back to "authenticated"`);
        assignedRole = await strapiInstance.db
          .query('plugin::users-permissions.role')
          .findOne({ where: { type: 'authenticated' } });

        if (!assignedRole) {
          ctx.status = 500;
          ctx.body = { error: { message: 'خطأ في الخادم: لم يتم العثور على الدور' } };
          return;
        }
      }

      // ── 4. تشفير كلمة المرور وإنشاء المستخدم ─────────────
      const hashedPassword = await bcrypt.hash(password, 10);

      const newUser = await strapiInstance.db
        .query('plugin::users-permissions.user')
        .create({
          data: {
            username,
            email:         email.toLowerCase(),
            password:      hashedPassword,
            provider:      'local',
            confirmed:     true,
            blocked:       false,
            vendeurStatus: isVendorBool ? (vendeurStatus || 'pending') : null,
            role:          assignedRole.id,
          },
        });

      // ── 5. إنشاء البروفايل إذا أُرسلت بيانات ─────────────
      if (firstName || lastName || phone) {
        try {
          await strapiInstance.db.query('api::profil.profil').create({
            data: {
              firstName:   firstName || null,
              lastName:    lastName  || null,
              phone:       phone     || null,
              birthDate:   birthDate || null,
              gender:      gender    || null,
              user:        newUser.id,
              publishedAt: new Date(),
            },
          });
        } catch (profileErr) {
          strapiInstance.log.error('[register] Failed to create profil:', profileErr);
        }
      }

      // ── 6. توليد JWT والرد ────────────────────────────────
      const jwt = strapiInstance
        .plugin('users-permissions')
        .service('jwt')
        .issue({ id: newUser.id });

      ctx.status = 200;
      ctx.body = {
        jwt,
        user: buildUserResponse(newUser, assignedRole),
      };

    } catch (err) {
      strapiInstance.log.error('[register] Unexpected error:', err.message, err.stack);
      ctx.status = 500;
      ctx.body = { error: { message: err.message || 'حدث خطأ غير متوقع أثناء التسجيل' } };
    }
  };

  // ── تسجيل الدخول ────────────────────────────────────────────────────────
  plugin.controllers.auth.callback = async (ctx) => {
    const strapiInstance = strapi;
    const provider = ctx.params && ctx.params.provider;

    // رفض أي OAuth provider (Google, Facebook, ...)
    if (provider && provider !== 'local') {
      ctx.status = 400;
      ctx.body = { error: { message: 'تسجيل الدخول عبر OAuth غير مدعوم' } };
      return;
    }

    // ── تسجيل الدخول العادي (local) فقط ──────────────────────
    try {
      await originalCallback(ctx);

      if (ctx.status === 200 && ctx.body && ctx.body.user) {
        const userId = ctx.body.user.id;
        const user = await strapiInstance.db
          .query('plugin::users-permissions.user')
          .findOne({ where: { id: userId }, populate: { role: true } });

        if (user) {
          const savedJwt = ctx.body.jwt;
          ctx.body = { jwt: savedJwt, user: buildUserResponse(user, user.role) };
        }
      }
    } catch (err) {
      if (ctx.status && ctx.status !== 200) return;
      strapiInstance.log.error('[callback:local] Unexpected error:', err);
      ctx.status = 500;
      ctx.body = { error: { message: 'حدث خطأ أثناء تسجيل الدخول' } };
    }
  };

  return plugin;
};
