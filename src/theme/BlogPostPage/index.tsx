import React, { type ReactNode } from "react";
import clsx from "clsx";
import {
  HtmlClassNameProvider,
  ThemeClassNames,
} from "@docusaurus/theme-common";
import {
  BlogPostProvider,
  useBlogPost,
} from "@docusaurus/plugin-content-blog/client";
import BlogLayout from "@theme/BlogLayout";
import BlogPostItem from "@theme/BlogPostItem";
import BlogPostPaginator from "@theme/BlogPostPaginator";
import BlogPostPageMetadata from "@theme/BlogPostPage/Metadata";
import BlogPostPageStructuredData from "@theme/BlogPostPage/StructuredData";
import TOC from "@theme/TOC";
import ContentVisibility from "@theme/ContentVisibility";
import Admonition from "@theme/Admonition";
import TypeIt from "typeit-react";
import type { Props } from "@theme/BlogPostPage";
import type { PropBlogPostContent } from "@docusaurus/plugin-content-blog";
import type { BlogSidebar } from "@docusaurus/plugin-content-blog";

function BlogSummary({
  content,
}: {
  content: PropBlogPostContent;
}): JSX.Element {
  try {
    const Data = require("@site/.docusaurus/ai-summary/default/aisummary.json");
    if (!content.metadata.editUrl) {
      console.warn(
        "No editUrl found in metadata, skipping AI summary generation"
      );
      return <></>;
    }
    const link = content.metadata.editUrl.split("/");
    const blog = link[link.length - 2],
      post = link[link.length - 1].replace(/\.(md|mdx)$/, "");
    if (!Data[blog] || !Data[blog][post]) {
      console.warn(
        "No ai-summary content found, skipping AI summary generation"
      );
      return <></>;
    }
    const summary = Data[blog][post];

    return (
      <Admonition type="danger" title="AI Summary" icon="🤖">
        <TypeIt options={{ speed: 7, cursor: false }}>{summary}</TypeIt>
      </Admonition>
    );
  } catch (e) {
    if (e.code === "MODULE_NOT_FOUND") {
      console.debug(
        "No ai-summary plugin found, skipping AI summary generation"
      );
    } else {
      console.warn(e);
    }
    return <></>;
  }
}

function BlogPostPageContent({
  sidebar,
  children,
}: {
  sidebar: BlogSidebar;
  children: ReactNode;
}): JSX.Element {
  const { metadata, toc } = useBlogPost();
  const { nextItem, prevItem, frontMatter } = metadata;
  const {
    hide_table_of_contents: hideTableOfContents,
    toc_min_heading_level: tocMinHeadingLevel,
    toc_max_heading_level: tocMaxHeadingLevel,
  } = frontMatter;
  return (
    <BlogLayout
      sidebar={sidebar}
      toc={
        !hideTableOfContents && toc.length > 0 ? (
          <TOC
            toc={toc}
            minHeadingLevel={tocMinHeadingLevel}
            maxHeadingLevel={tocMaxHeadingLevel}
          />
        ) : undefined
      }
    >
      <ContentVisibility metadata={metadata} />

      <BlogPostItem>{children}</BlogPostItem>

      {(nextItem || prevItem) && (
        <BlogPostPaginator nextItem={nextItem} prevItem={prevItem} />
      )}
    </BlogLayout>
  );
}

export default function BlogPostPage(props: Props): JSX.Element {
  const BlogPostContent = props.content;
  return (
    <BlogPostProvider content={props.content} isBlogPostPage>
      <HtmlClassNameProvider
        className={clsx(
          ThemeClassNames.wrapper.blogPages,
          ThemeClassNames.page.blogPostPage
        )}
      >
        <BlogPostPageMetadata />
        <BlogPostPageStructuredData />
        <BlogPostPageContent sidebar={props.sidebar}>
          <BlogSummary content={props.content} />
          <BlogPostContent />
        </BlogPostPageContent>
      </HtmlClassNameProvider>
    </BlogPostProvider>
  );
}
