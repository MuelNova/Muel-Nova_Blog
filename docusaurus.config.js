// dotenv
require("dotenv").config();

// @ts-check
// Note: type annotations allow type checking and IDEs autocompletion
const { themes } = require("prism-react-renderer");
const lightCodeTheme = themes.github;
const darkCodeTheme = themes.dracula;

import remarkMath from "remark-math";
import rehypeKatex from "rehype-katex";

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: "ネコのメモ帳",
  tagline: "Meow~",
  url: "https://nova.gal",
  baseUrl: "/",
  onBrokenLinks: "warn",
  onBrokenMarkdownLinks: "warn",
  favicon: "img/nova-logo-par.png",
  titleDelimiter: "🐱",
  staticDirectories: ["src/static"],

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: "MuelNova", // Usually your GitHub org/user name.
  projectName: "Muel-Nova_Blog", // Usually your repo name.

  // Even if you don't use internalization, you can use this field to set useful
  // metadata like html lang. For example, if your site is Chinese, you may want
  // to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: "zh-Hans",
    locales: ["zh-Hans", "en"],
    path: "src/i18n",
  },

  customFields: {
    OPENAI_API_KEY: process.env.OPENAI_API_KEY,
  },

  stylesheets: [
    {
      href: "https://cdn.jsdelivr.net/npm/katex@0.13.24/dist/katex.min.css",
      type: "text/css",
      integrity:
        "sha384-odtC+0UGzzFL/6PNoE8rX/SPcQDXBJ+uRepguP4QkPCm2LBxH3FA3y+fKSiJ+AmM",
      crossorigin: "anonymous",
    },
  ],

  markdown: {
    format: "detect",
    mdx1Compat: {
      admonitions: true,
    },
  },

  presets: [
    [
      "classic",
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        pages: {
          path: "src/contents/pages",
        },
        docs: false,
        sitemap: {
          changefreq: "daily",
          priority: 0.5,
          ignorePatterns: ["/tags/**"],
          filename: "sitemap.xml",
        },
        blog: false,
        theme: {
          customCss: [require.resolve("./src/theme/css/custom.scss")],
        },
      }),
    ],
  ],

  plugins: [
    [
      "@docusaurus/plugin-content-docs",
      {
        id: "default",
        path: "src/contents/library",
        routeBasePath: "library",
        editUrl: "https://github.com/MuelNova/Muel-Nova-Blog/tree/main/",
      },
    ],
    [
      "@docusaurus/plugin-content-blog",
      {
        id: "reproducing",
        routeBasePath: "reproducing",
        path: "src/contents/reproducing",
        blogSidebarCount: "ALL",
        blogSidebarTitle: "♻️复现",
        feedOptions: {
          type: "rss",
          copyright: `Copyright © ${new Date().getFullYear()} NovaNo1r with ❤`,
        },
        authorsMapPath: "../blog/authors.yml",
        remarkPlugins: [remarkMath],
        rehypePlugins: [rehypeKatex],
      },
    ],

    [
      "@docusaurus/plugin-content-blog",
      {
        id: "default",
        path: "src/contents/blog",
        blogTitle: "BLOG",
        blogSidebarTitle: "Written with 😢tears and loves❤",
        blogSidebarCount: "ALL",
        showReadingTime: true,
        // Please change this to your repo.
        // Remove this to remove the "edit this page" links.
        editUrl: "https://github.com/MuelNova/NovaNo1r-Blog/tree/main/",
        feedOptions: {
          type: "rss",
          description: "Nova 是一个做 PWN 的二次元，Nova 的博客用于输出无营养内容。",
          copyright: `Copyright © ${new Date().getFullYear()} NovaNo1r with ❤`,
        },
        remarkPlugins: [remarkMath],
        rehypePlugins: [rehypeKatex],
      },
    ],

    [
      "@docusaurus/plugin-content-blog",
      {
        id: "posts",
        path: "src/contents/posts",
        routeBasePath: "posts",
        blogSidebarCount: "ALL",
        // Please change this to your repo.
        // Remove this to remove the "edit this page" links.
        authorsMapPath: "../blog/authors.yml",
        editUrl: "https://github.com/MuelNova/NovaNo1r-Blog/tree/main/",

        feedOptions: {
          type: "rss",
          copyright: `Copyright © ${new Date().getFullYear()} NovaNo1r with ❤`,
        },
      },
    ],
    "docusaurus-plugin-sass",
    // 'plugin-image-zoom',
    // [
    //   '@docusaurus/plugin-google-gtag',
    //   {
    //     trackingID: process.env.GTAG,
    //     anonymizeIP: true,
    //   },
    // ],
    [
      require.resolve("./src/plugins/ai-summary"),
      {
        OPENAI_API_KEY: process.env.OPENAI_API_KEY,
        OPENAI_BASE_URL: process.env.OPENAI_BASE_URL,
        OPENAI_SUMMARY_MODEL: process.env.OPENAI_SUMMARY_MODEL,
      },
    ],
    [
      require.resolve("./src/plugins/ai-translate"),
      {
        OPENAI_API_KEY: process.env.OPENAI_API_KEY,
        OPENAI_BASE_URL: process.env.OPENAI_BASE_URL,
        OPENAI_TRANSLATE_MODEL: process.env.OPENAI_TRANSLATE_MODEL,
        OPENAI_TOKEN_SIZE: process.env.OPENAI_TOKEN_SIZE,
      },
    ],
  ],

  themes: [
    // ... Your other themes.
    [
      require.resolve("@easyops-cn/docusaurus-search-local"),
      {
        // ... Your options.
        // `hashed` is recommended as long-term-cache of index file is possible.
        hashed: true,
        indexBlog: true,
        docsRouteBasePath: ["blockchain", "pwn"],
        language: ["en", "zh"],

        // For Docs using Chinese, The `language` is recommended to set to:
        // ```
        // language: ["en", "zh"],
        // ```
      },
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    {
      giscus: {
        repo: process.env.GISCUS_REPO,
        repoId: process.env.GISCUS_REPO_ID,
        category: process.env.GISCUS_CATEGORY,
        categoryId: process.env.GISCUS_CATEGORY_ID,
        lightCss: process.env.GISCUS_LIGHT_CSS,
        darkCss: process.env.GISCUS_DARK_CSS,
      },
      navbar: {
        title: "Muel-Nova",
        logo: {
          alt: "SiteLogo",
          src: "img/nova-logo-par.png",
        },
        items: [
          // {
          //   type: 'doc',
          //   docId: '',
          //   position: 'right',
          //   label: '🤡文章',
          // },
          { to: "/posts", label: "🤡文章", position: "left" },
          { to: "/reproducing", label: "♻️复现", position: "left" },
          {
            type: "localeDropdown",
            position: "right",
          },
          { to: "/blog", label: "📝博客", position: "left" },
          { to: "/library", label: "♿️知识库", position: "left" },
          {
            href: "https://github.com/MuelNova",
            label: "GitHub",
            position: "right",
          },
          {
            href: "/about",
            label: "关于",
            position: "right",
          },
          {
            href: "/links",
            label: "友情链接",
            position: "right",
          },
        ],
      },
      footer: {
        style: "dark",
        links: [
          {
            title: "Here",
            items: [
              { to: "/blog", label: "📝博客" },
              { to: "/library", label: "♿️知识库" },
            ],
          },
          {
            title: "There",
            items: [
              { to: "/reproducing", label: "♻️复现" },
              { to: "/posts", label: "🤡文章" },
            ],
          },
          {
            title: "Who",
            items: [
              {
                label: "关于",
                href: "/about",
              },
              {
                label: "Follow",
                href: "https://app.follow.is/profile/56300998939738112",
              },
              {
                label: "Steam",
                href: "https://steamcommunity.com/id/muelnova",
              },
              {
                label: "Github",
                href: "https://github.com/MuelNova",
              },
            ],
          },
          {
            title: "Contact",
            items: [
              {
                label: "Tencent QQ",
                href: "https://qm.qq.com/q/2liGTvjIM",
              },
              {
                label: "Mail",
                href: "mailto:muel@nova.gal",
              },
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} <a href="/about">MuelNova</a>. Built with <a href="https://docusaurus.io/">Docusaurus</a> filling with ❤ and 🥛`,
      },
      prism: {
        theme: lightCodeTheme,
        darkTheme: darkCodeTheme,
        additionalLanguages: [
          "powershell",
          "bash",
          "python",
          "diff",
          "json",
          "cpp",
        ],
      },
      tableOfContents: {
        minHeadingLevel: 2,
        maxHeadingLevel: 5,
      },
      imageZoom: {
        // CSS selector to apply the plugin to, defaults to '.markdown img'
        selector: ".markdown img",
        // Optional medium-zoom options
        // see: https://www.npmjs.com/package/medium-zoom#options
        options: {
          margin: 24,
          background: "#222222",
          // scrollOffset: 40,
          // container: '#zoom-container',
          // template: '#zoom-template',
        },
      },
      // announcementBar: {
      // id: 'Warning',
      // content:
      //   '网站正在重写前端，你可能会遇到一些问题阻止你的正常访问！',
      // backgroundColor: '#fafbfc',
      // textColor: '#091E42',
      // isCloseable: true,
      // },
    },
};

module.exports = config;
