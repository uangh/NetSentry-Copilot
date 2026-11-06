# GitHub 与 Pages 发布

推荐仓库名：`NetSentry-Copilot`。此目录是可提交副本；不要上传原工程或私有冻结ZIP。没有全项目新开源许可证，不要在GitHub初始化时自动添加MIT等许可证。

当前仓库：[uangh/NetSentry-Copilot](https://github.com/uangh/NetSentry-Copilot)。当前作品集：[GitHub Pages](https://uangh.github.io/NetSentry-Copilot/)。已按用户授权完成公开上传与 Actions 部署，以下创建步骤供重新发布或复用时参考，无需重复创建。

## 创建和上传

在GitHub选择 New repository，填写仓库名并选择Public；使用空仓库，不额外初始化README、.gitignore或许可证。只有确认账号和仓库后才配置remote。不要覆盖同名已有仓库。

本机需Git和GitHub CLI。采用浏览器登录，不在聊天或命令行参数中粘贴PAT：

```powershell
gh auth login --hostname github.com --web --git-protocol https
gh auth setup-git
```

确认身份：`gh api user --jq .login`。若Git尚无作者信息，在此公开目录内用自己的真实身份执行 `git config user.name "你的名字"`、`git config user.email "你的已验证邮箱或GitHub隐私邮箱"`；不能伪造历史作者。

完成文件审阅后：

```powershell
git status --short
git add .
git commit -m "Prepare NetSentry public source and static portfolio"
git branch -M main
git remote add origin https://github.com/YOUR_ACCOUNT/NetSentry-Copilot.git
git push -u origin main
```

`YOUR_ACCOUNT` 为明确占位，必须替换成实际已登录账号；如果origin已正确配置，不重复添加。不要使用force push，不上传运行资产或真实密钥。也可在授权后使用 `gh repo create NetSentry-Copilot --public --source . --remote origin --push`，该命令会实际创建和推送，不能把它当作只读检查。

## 配置 Pages

仓库 Settings → Pages → Build and deployment → Source 选择 **GitHub Actions**。再到 Actions → Publish static portfolio → Run workflow；之后main的site或工作流更新也会触发发布。

工作流使用GitHub官方文档中的 `checkout@v6`、`configure-pages@v5`、`upload-pages-artifact@v4` 和 `deploy-pages@v4`；只上传 **site/**。不安装Python/ML依赖、不启动后端、不调用Gemini。官方依据：[自定义Pages工作流](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages)。

## 确认成功

1. Actions运行成功，`github-pages`环境显示部署URL。
2. 打开GitHub返回的真实地址；预期格式为 `https://YOUR_ACCOUNT.github.io/NetSentry-Copilot/`，部署前不要把占位当作已上线链接。
3. 用电脑及手机打开主页、图集、精简案例、来源说明，确认图片和中文显示正常。
4. 打开仓库Code页验证公开源码；Pages只展示site，不展示仓库其他目录。
5. 把真实仓库/Pages地址写回README；保留当前Sites入口也可以，但须区分托管来源。

没有运行资产时不能用Pages测试预测、真实调查或审核。静态页面没有Key输入框，也没有可直接调用Gemini的逻辑。
