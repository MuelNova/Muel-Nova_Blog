// 获取 docusaurus 配置
const path = require("path");
const fs = require("fs");
import {
  LoadContext,
  Plugin,
  PluginOptions,
  PluginContentLoadedActions,
} from "@docusaurus/types";
import openai from "openai";

interface BlogPluginOptions extends PluginOptions {
  id?: string;
  path?: string;
  routeBasePath?: string;
  [key: string]: any;
}

interface PluginConfig extends PluginOptions {
  OPENAI_API_KEY?: string;
  OPENAI_BASE_URL?: string;
  OPENAI_SUMMARY_MODEL?: string;
  OPENAI_SUMMARY_SYSTEM_PROMPT?: string;
}

export default async function AISummary(
  context: LoadContext,
  options: PluginConfig
): Promise<Plugin> {
  // ...
  return {
    name: "ai-summary",
    async loadContent() {
      const { siteConfig } = context;
      const blogPlugins = siteConfig.plugins.filter(
        (plugin) =>
          Array.isArray(plugin) &&
          plugin[0] === "@docusaurus/plugin-content-blog"
      );

      const summaries: { [key: string]: { [key: string]: string } } = {};
      let skipFlag = false;

      if (!options || !options.OPENAI_API_KEY) {
        console.warn(
          "OPENAI_API key is not set in siteConfig.customFields, skipping AI summary generation"
        );
        skipFlag = true;
      }

      const openaiClient = skipFlag
        ? new openai({ apiKey: "dummy_api" })
        : new openai({
            apiKey: options.OPENAI_API_KEY,
            baseURL: options.OPENAI_BASE_URL,
          });
      const model = (options.OPENAI_SUMMARY_MODEL as string) || "gpt-4o";
      const systemPrompt =
        (options.OPENAI_SUMMARY_SYSTEM_PROMPT as string) ||
        `你是一位专业的内容总结助手，你的任务是根据用户提供的文本生成简洁的总结。
                请确保总结清晰、简明，抓住文章的主要内容和作者的主要经历。
                注意，你需要使用和文章主要语言相同的语种，更推荐你不使用 markdown。
                在数个自然段内完成总结，注意 nova 即为博客作者，且为男性。`;
      const generateSummary = async (content: string) => {
        const response = await openaiClient.chat.completions.create({
          model: model,
          messages: [
            {
              role: "system",
              content: systemPrompt,
            },
            {
              role: "user",
              content,
            },
          ],
        });
        return response.choices[0]?.message?.content;
      };

      for (const blogPlugin of blogPlugins) {
        if (!blogPlugin) {
          console.warn("No blog plugin found, skipping AI summary generation");
          skipFlag = true;
        }
        const pluginOptions = blogPlugin[1] as BlogPluginOptions;
        const blogPath = pluginOptions.path;
        const blogRoute = pluginOptions.routeBasePath || "blog";

        const blogDir = path.join(context.siteDir, blogPath);
        const files = fs.readdirSync(blogDir);

        for (const file of files) {
          // 判断是否是 md 或者 mdx 文件
          if (
            (!file.endsWith(".md") && !file.endsWith(".mdx")) ||
            file.startsWith("__")
          ) {
            continue;
          }
          const filePath = path.join(blogDir, file);
          const fileName = file.replace(/\.(md|mdx)$/, "").replace(" ", "-");
          // 判断是不是文件夹
          if (fs.statSync(filePath).isDirectory()) {
            continue;
          }
          let content = fs.readFileSync(filePath, "utf-8");
          // 使用正则表达式全局替换代码块和引用块
          const codeBlockRegex = /```[^]+?```/g;
          content = content.replace(codeBlockRegex, "");

          // 替换多行引用块
          const quoteRegex = />>[^]+/g;
          content = content.replace(quoteRegex, "");

          // 检查文件是否需要更新摘要（可以根据文件的时间戳或其他标志）
          const summaryFilePath = filePath.replace(/\.(md|mdx)$/, ".summary");
          const summaryExists = fs.existsSync(summaryFilePath);
          if (summaryExists) {
            const summaryStats = fs.statSync(summaryFilePath);
            const blogStats = fs.statSync(filePath);
            if (summaryStats.mtime >= blogStats.mtime) {
              summaries[blogRoute] = summaries[blogRoute] || {};
              summaries[blogRoute][fileName] = fs.readFileSync(
                summaryFilePath,
                "utf-8"
              );
              continue;
            }
          }

          // 生成摘要
          if (skipFlag) continue;
          console.log("Generating summary for", file);
          const response = await generateSummary(content);
          if (!response) {
            console.warn(`Failed to generate summary for ${file}`);
            continue;
          }
          summaries[blogRoute] = summaries[blogRoute] || {};
          summaries[blogRoute][file] = response;
          fs.writeFileSync(summaryFilePath, response);
        }
      }
      return { aisummary: summaries };
    },

    async contentLoaded({
      content,
      actions,
    }: {
      content: any;
      actions: PluginContentLoadedActions;
    }) {
      const { createData } = actions;
      createData("aisummary.json", JSON.stringify(content.aisummary, null, 2));
    },
    /* other lifecycle API */
  };
}
