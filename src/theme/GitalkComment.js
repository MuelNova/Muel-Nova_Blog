import React, {Component} from 'react'
import 'gitalk/dist/gitalk.css'
import './GitalkComment.css'
import Gitalk from 'gitalk'
import {Md5} from 'ts-md5'

class GitalkComment extends Component{
  componentDidMount(){
    var gitalk = new Gitalk({
        clientID: '',
        clientSecret: '',
        repo: 'NovaNo1r-gitalk',      // The repository of store comments,
        owner: 'Nova-Noir',
        admin: ['Nova-Noir'],
        id: Md5.hashStr(location.href),      // Ensure uniqueness and length less than 50
        distractionFreeMode: false  // Facebook-like distraction free mode
    })
    
    gitalk.render('gitalk-container')
  }
  render(){
    return <div id="gitalk-container"></div>
  }
}
export default GitalkComment;