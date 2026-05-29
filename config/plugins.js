module.exports = ({ env }) => ({

  // ── Upload Cloudinary ─────────────────────────────────
  upload: {
    config: {
      provider: 'cloudinary',
      providerOptions: {
        cloud_name: env('CLOUDINARY_NAME'),
        api_key:    env('CLOUDINARY_KEY'),
        api_secret: env('CLOUDINARY_SECRET'),
      },
      actionOptions: {
        upload: {},
        uploadStream: {},
        delete: {},
      },
    },
  },

  // ── Import / Export ───────────────────────────────────
  'import-export-entries': {
    enabled: true,
  },

  // ── Users & Permissions ───────────────────────────────
  'users-permissions': {
    config: {
      jwt: {
        expiresIn: '7d',
      },
    },
  },

});
