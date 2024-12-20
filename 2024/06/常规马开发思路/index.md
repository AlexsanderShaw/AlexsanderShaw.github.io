# 实战场景下马的开发思路（一）-- 序


记录下实战场景下马的开发思路。

<!--more-->

# 实战场景下马的开发思路（一）-- 序

## 写在前面

​	写个系列吧，主要是涉及一些常见马的设计和使用方式，可能会跟社工结合一下，看看到时候具体怎么想。这里先简单说下为什么要跟社工结合吧。慢慢来～

## 0. 马的定位

​	讨论到马，不能直接就关注马的技术层面，我认为每个做马的人，都应该先会社会工程，最起码要了解一些常见的技术和思路。术业有专攻这句话很对，但是社工钓鱼因为是在马的攻击流程的前面，如果没有鱼，马就无处施展（不包含打点的情况）。而且，不同的钓鱼方式，会给马的制作方法提出不同的要求。所以我们不能一概而论，一种马走天下。

​	马是一种消耗型资源，因为攻防对抗强度的提升，攻击方式的公开，即意味着防守能力的提升。而挖掘一种新的攻击方式，可能投入的资源会比较大。所以在使用马时，需要考虑一下综合因素。不要不管不顾，直接全上。

### 1. 敲门马

​	直接和目标“接触”的马，不管目标是什么人，目标是知道这种马文件本身的存在的。但是能不能意识到这是马，就看攻击方社工能力和防守方安全意识的高低了。

​	这种马一般作为敲门砖，有些大佬称它为冲锋马。个人对这个称呼不是很认同。冲锋马的概念应该是来自于web攻防，是为了对抗流量检测设备的一种特殊类型的webshell，个人感觉一句话这种更适合冲锋马的概念。即使后续冲锋马被清理，留下的更复杂或完整的后门程序可以继续运行。因为生产场景的原因，受到攻击的服务器无法关停或者停止运行服务，这就导致虽然冲锋马被清理，但是后渗透留下的后门程序可以继续运行。

​	但如果来到PC场景，个人感觉概念上就不能称为冲锋马了。实战场景下，PC端的攻防对抗和web服务器的场景还不太一样。如果我们的第一个马触发告警或者被发现，那么PC是可以即刻进行断网隔离、关停主机等操作的。那么即使做了后渗透的持久化马，还是又可能会在全面排查的过程中被清理掉。

​	后渗透阶段需要的马的要求更高，这就要求我们的“敲门马”在完成基本的目标上线功能后，不要再额外添加其他功能，避免引起PC告警。在上传持久化马并且稳定运行后，它就可以结束生命周期了。

​	有点类似于web攻防场景下的一句话，主要作用是让目标上线，形式不用固定，技术实现方式不用固定，技术含量不一定十分高级。只要在其生命周期内，我们能够有时间上传持久化马即可。所以，理论上来说，这种马要求功能简单、特征少、体积小、人性迷惑性高。

### 2. 持久化马

​	不直接和目标“接触”的马，理想情况下目标全程无感知马的存在。功能比较完善，具备较强的隐匿能力（自我隐藏和伪装）和生存能力（免杀、权限维持）。

​	主要的免杀对抗体现在这里，最优秀的免杀能力应该放在该类马中，该马的好坏，直接决定了后渗透其他阶段的成果。

## 1. 马的选择因素

### 0. 废话

​	马的选择和制作不应该是单一的形式，在各种不同的因素的综合影响下，应该根据不同的情况去选择不同类型的马。但是目前实战场景下，大家关注的点都是我的马免不免杀、我的马是远程加载还是本地加载。关注这个点没有问题，因为这是技术层面很重要的因素。但是个人感觉更多的应该还是考虑下攻击场景，根据不同的攻击场景去选择。单文件马不一定就比分离加载的马更有风险，在某些场景下，它可能更有效率。

### 1. 场景因素

1. 单一场景：低对抗，功能单一，上线就行，后续会上传持久化马

   此时的“敲门马”不一定非要是基于CS做的那种功能完善的“大马”，只要具备命令执行和文件上传的功能和基本的免杀能力即可。因为后渗透阶段的所有操作我们都是基于持久化马来完成的。

2. 复杂场景：高对抗，功能复杂

   对抗激烈，要求免杀能力较强，在敲门马阶段就要做好攻防的对抗；功能复杂，要求功能完善（如屏幕监控、键盘记录等）。

### 2. 团队因素

​	一般情况下，实战的攻击应该是一个完整的红队配合完成，但是在大部分实际情况下，没有那么完善的人员配置。所以，每个人的技术能力就会存在差异。这个时候，每个人做马的思路和技术栈是不一样的，不必要非要强调某种技术的好坏。适合自己的，就是最好的。所以，选择自己习惯的、喜欢的，就可以。

### 3. 时间因素

​	项目的时间因素决定使用的马的种类，因为有些马的功能是为了长久驻留使用的，有的是为了短期存活使用的。

​	例如我们的国家攻防演练，时间周期以往都是两周，理论上来说，鱼上钩了，这个时候应该上持久化马。但是我们最大的时间要求就是14天，也就是说我们的马只要存活14天即可（其实大部分情况下没有这么长的时间要求，一般情况都是7天左右）。

​	而像实际的APT的这种场景，马的存活时间要求长得多（多为rootkit级别），他们的制作方式肯定是跟我们的攻防演练不一样的。

## 2. 社工和马

​	良好的社会功能力，是制作优秀马的基础。

### 1. 社会工程

​	我始终认为社会工程和做马是分不开的，社工的文案和话术也会对使用的马的制作方式产生影响。

​	例如我们在IM场景下的社工钓鱼，假设我们最终跟目标沟通的是发送文档（招标文件、通知文件之类）。理论上来说，最理想的情况是给文档类文件。但是因为国内的特殊情况，文档类的马用不了（比如国外常见的宏，国内是大部分默认就禁止的）。这个时候，如果我们直接给exe后缀的马，就存在直接暴露的风险；如果给压缩包，能稍微降低一下目标的警觉。其次，文档类的文件体积不会很大，如果这个时候我们给的马的体积过大或者过小，都会引起目标的怀疑。因为很多IM软件在发送文件的时候，会直接显示文件的体积。

​	再比如，在内网水坑钓鱼的场景下，一般是让下载文件，msi格式的文件就要比exe格式的文件成功率高，利用的就是人的心理。大部分人对msi不了解，而且很多正规安装软件就是msi格式，但是exe人们见的很多，很容易就怀疑上了。

​	所以，根据对应的场景和社工文案，发送对应的格式的马。

### 2. 相辅相成

​	先学点社工再学马，会事半功倍。因为你对你的马的各种使用场景会有深入的理解，最重要的是，在你发现一种新的技术的时候，能够思考到它在实战场景下的使用方式。

​	

## 

 
