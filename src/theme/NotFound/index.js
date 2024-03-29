import React from 'react';
import Translate, {translate} from '@docusaurus/Translate';
import {PageMetadata} from '@docusaurus/theme-common';
import Layout from '@theme/Layout';
import './NotFound.css'
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';

export default function NotFound() {
  return (
    <>
      <PageMetadata
        title={translate({
          id: 'theme.NotFound.title',
          message: 'Page Not Found',
        })}
      />
      <Layout>
        <main className="container margin-vert--xl">
          <div className='hero'>
            <div className='hero__text'>
            <h1 className="hero__title">
                <Translate
                  id="theme.NotFound.title"
                  description="The title of the 404 page">
                  Page Not Found
                </Translate>
              </h1>
              <p>
                <Translate
                  id="theme.NotFound.p1"
                  description="The first paragraph of the 404 page">
                  We could not find what you were looking for.
                </Translate>
              </p>
              <p>
                <Translate
                  id="theme.NotFound.p2"
                  description="The 2nd paragraph of the 404 page">
                  Please contact the owner of the site that linked you to the
                  original URL and let them know their link is broken.
                </Translate> 
              </p>
              <a href={useDocusaurusContext().siteConfig.baseUrl}>
              <Translate
                  id="theme.NotFound.a"
                  description="The addr of the 404 page">
                  再回去找找
                </Translate>
              </a>
            </div>
            <div className='hero__img'>
              <img src={require("@site/src/static/img/404/" + Math.floor(Math.random()*20) + ".jpg").default}/>
            </div>
          </div>
        </main>
      </Layout>
    </>
  );
}
