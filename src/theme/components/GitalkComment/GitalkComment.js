import React from 'react'
import 'gitalk/dist/gitalk.css'
import GitalkComponent from "gitalk/dist/gitalk-component";
import './GitalkComment.css'
import {Md5} from 'ts-md5'
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';

export default () => {
  const {
    siteConfig: {customFields},
  } = useDocusaurusContext();
  // we can only get a string here so a simple conversion
  let admin = customFields.gitalkAdmin
  try {
    admin = JSON.parse(admin.replace(/'/g, '"'));
  }
  catch(e) {}

  return (<GitalkComponent options={{
    clientID: customFields.gitalkClientID,
    clientSecret: customFields.gitalkSecret,
    repo: customFields.gitalkREPO,      // The repository of store comments,
    owner: customFields.gitalkOwner,
    admin: admin,
    id: Md5.hashStr(location.href),      // Ensure uniqueness and length less than 50
    distractionFreeMode: true  // Facebook-like distraction free mode
  }} />)
};