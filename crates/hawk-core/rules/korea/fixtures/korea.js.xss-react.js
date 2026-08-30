// ruleid: korea.js.xss-react
<div dangerouslySetInnerHTML={{ __html: userInput }} />
// ok: korea.js.xss-react
<div>{userInput}</div>
