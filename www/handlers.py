#!/usr/bin/env python3
# -*- coding: utf-8 -*-


' url handlers '

import re, time, json, logging, hashlib, base64, asyncio

import markdown2

from aiohttp import web

from coroweb import get, post
from apis import Page, APIValueError, APIResourceNotFoundError,APIPermissionError

from models import User, Comment, Blog, next_id
from config import configs



COOKIE_NAME = 'awesession'
_COOKIE_KEY = configs.session.secret

def check_admin(request):
    if request.__user__ is None or  request.__user__.admin < 1:
        raise APIPermissionError()

#def check_superadmin(request):
    
        
def get_page_index(page_str):
    p = 1
    try:
        p = int(page_str)
    except ValueError as e:
        pass
    if p < 1:
        p = 1
    return p

def user2cookie(user, max_age):
    '''
    Generate cookie str by user.
    '''
    # build cookie string by: id-expires-sha1
    expires = str(int(time.time() + max_age))
    s = '%s-%s-%s-%s' % (user.id, user.passwd, expires, _COOKIE_KEY)
    L = [user.id, expires, hashlib.sha1(s.encode('utf-8')).hexdigest()]
    return '-'.join(L)

def text2html(text):
    lines = map(lambda s: '<p>%s</p>' % s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'), filter(lambda s: s.strip() != '', text.split('\n')))   #剔除掉空格和换行符，替换在HTML中有特殊含义的字符
    return ''.join(lines)
    
def time2date(t):
    delta = int(time.time() - t)
    if delta < 60:
        return u'1分钟前'
    if delta < 3600:
        return u'%s分钟前' % (delta // 60)
    if delta < 86400:
        return u'%s小时前' % (delta // 3600)
    if delta < 604800:
        return u'%s天前' % (delta // 86400)
    dt = datetime.fromtimestamp(t)
    return u'%s年%s月%s日' % (dt.year, dt.month, dt.day)
    

@asyncio.coroutine
def cookie2user(cookie_str):
    '''
    Parse cookie and load user if cookie is valid.
    '''
    if not cookie_str:
        return None
    try:
        L = cookie_str.split('-')
        if len(L) != 3:
            return None
        uid, expires, sha1 = L
        if int(expires) < time.time():
            return None
        user = yield from User.find(uid)
        if user is None:
            return None
        s = '%s-%s-%s-%s' % (uid, user.passwd, expires, _COOKIE_KEY)
        if sha1 != hashlib.sha1(s.encode('utf-8')).hexdigest():
            logging.info('invalid sha1')
            return None
        #user.passwd = '******'
        return user
    except Exception as e:
        logging.exception(e)
        return None

#首页
@get('/')
@asyncio.coroutine
def index(request):
    logging.info('request.__user__:===========>%s'%request.__user__)
    blogs = yield from Blog.findAll(orderBy='created_at desc',limit=5)
    return {
        '__template__': 'blogs.html',
        'blogs': blogs
    }

    #日志详情页
@get('/blog/{id}')
@asyncio.coroutine
def get_blog(id):
    blog = yield from Blog.find(id)
    comments = yield from Comment.findAll('blog_id=?', [id], orderBy='created_at desc')
    for c in comments:
        c.html_content = text2html(c.content)
    blog.html_content = markdown2.markdown(blog.content)
    return {
        '__template__': 'blog.html',
        'blog': blog,
        'comments': comments
    }

    #注册页
@get('/register')
def register():
    return {
        '__template__': 'register.html'
    }

    #登陆页
@get('/signin')
def signin():
    return {
        '__template__': 'signin.html'
    }

    #登录验证API
@post('/api/authenticate')
@asyncio.coroutine
def authenticate(*, email, passwd):
    if not email:
        raise APIValueError('email', 'Invalid email.')
    if not passwd:
        raise APIValueError('passwd', 'Invalid password.')
    users = yield from User.findAll('email=?', [email])
    if len(users) == 0:
        raise APIValueError('email', 'Email not exist.')
    user = users[0]
    # check passwd:
    sha1 = hashlib.sha1()
    sha1.update(user.id.encode('utf-8'))
    sha1.update(b':')
    sha1.update(passwd.encode('utf-8'))
    if user.passwd != sha1.hexdigest():
        raise APIValueError('passwd', 'Invalid password.')
    # authenticate ok, set cookie:
    r = web.Response()
    r.set_cookie(COOKIE_NAME, user2cookie(user, 86400), max_age=86400, httponly=True)
    user.passwd = '******'
    r.content_type = 'application/json'
    r.body = json.dumps(user, ensure_ascii=False).encode('utf-8')
    logging.info('================>%s---------------------%s'%(isinstance(r,web.StreamResponse),dir(r)))
    return r
    
    #用户注册API
@post('/api/users')
@asyncio.coroutine
def api_register_user(*, email, name, passwd):
    if not name or not name.strip():
        raise APIValueError('name')
    if not email or not _RE_EMAIL.match(email):
        raise APIValueError('email')
    if not passwd or not _RE_SHA1.match(passwd):
        raise APIValueError('passwd')
    users = yield from User.findAll('email=?', [email])
    if len(users) > 0:
        raise APIError('register:failed', 'email', 'Email is already in use.')
    uid = next_id()
    sha1_passwd = '%s:%s' % (uid, passwd)
    user = User(id=uid, name=name.strip(), email=email, passwd=hashlib.sha1(sha1_passwd.encode('utf-8')).hexdigest(), image='http://www.gravatar.com/avatar/%s?d=mm&s=120' % hashlib.md5(email.encode('utf-8')).hexdigest())
    yield from user.save()
    # make session cookie:
    r = web.Response()
    r.set_cookie(COOKIE_NAME, user2cookie(user, 86400), max_age=86400, httponly=True)
    user.passwd = '******'
    r.content_type = 'application/json'
    r.body = json.dumps(user, ensure_ascii=False).encode('utf-8')
    return r

    #登出页
@get('/signout')
def signout(request):
    referer = request.headers.get('Referer')   #Referer 从哪个链接访问的
    r = web.HTTPFound(referer or '/')
    r.set_cookie(COOKIE_NAME, '-deleted-', max_age=0, httponly=True)
    logging.info('user signed out.')
    return r                    #定位到当前链接或首页，设置cookie过期

    #日志管理页
@get('/manage/blogs')
def manage_blogs(*, page='1'):
    return {
        '__template__': 'manage_blogs.html',
        'page_index': get_page_index(page)
    }    

    #日志创建页
@get('/manage/blogs/create')
def manage_create_blog():
    return {
        '__template__': 'manage_blog_edit.html',
        'id': '',
        'action': '/api/blogs'
    }

_RE_EMAIL = re.compile(r'^[a-z0-9\.\-\_]+\@[a-z0-9\-\_]+(\.[a-z0-9\-\_]+){1,4}$')
_RE_SHA1 = re.compile(r'^[0-9a-f]{40}$')

    #删除日志API
@post('/api/blogs/{id}/delete')
async def api_blog_delete(request,*,id):
    check_admin(request)
    blog=await Blog.find(id)
    if blog:
        await blog.remove()
        logging.info('success delete blog : %s'%blog.name)
        comments=await Comment.findbykey('blog_id',id)              #删除与博客相关的评论
        logging.info(comments)
        for comment in comments:
            await comment.remove()
    logging.info('success delete all comments about the blog :%s'%blog.name)    
    return blog

    #获取指定ID日志（查看日志详情）
@get('/api/blogs/{id}')
@asyncio.coroutine
def api_get_blog(*, id):
    blog = yield from Blog.find(id)
    return blog

    #创建日志API
@post('/api/blogs')
@asyncio.coroutine
def api_create_blog(request, *, name, summary, content):          #接收request参数，使用__user__信息
    if not name or not name.strip():
        raise APIValueError('name', 'name cannot be empty.')
    if not summary or not summary.strip():
        raise APIValueError('summary', 'summary cannot be empty.')
    if not content or not content.strip():
        raise APIValueError('content', 'content cannot be empty.')
    blog = Blog(user_id=request.__user__.id, user_name=request.__user__.name, user_image=request.__user__.image, name=name.strip(), summary=summary.strip(), content=content.strip())
    yield from blog.save()
    return blog

    #修改日志API
@post('/api/blogs/modify')
@asyncio.coroutine
def api_modify_blog(request, *, name, summary, content,id):          #接收request参数，使用__user__信息
    oldblog=yield from Blog.find(id)
    if oldblog:
        if  oldblog.user_id != request.__user__.id:
            raise APIPermissionError("you are not allowed to edit other user's blog")
        yield from oldblog.remove()
        logging.info('remove existed blog：%s'%oldblog.name)
    if not name or not name.strip():
        raise APIValueError('name', 'name cannot be empty.')
    if not summary or not summary.strip():
        raise APIValueError('summary', 'summary cannot be empty.')
    if not content or not content.strip():
        raise APIValueError('content', 'content cannot be empty.')
    blog = Blog(user_id=request.__user__.id, user_name=request.__user__.name, user_image=request.__user__.image, name=name.strip(), summary=summary.strip(), content=content.strip())
    yield from blog.save()
    return blog
    

    #获取某一页码的日志
@get('/api/blogs')
@asyncio.coroutine
def api_blogs(*, page='1'):
    page_index = get_page_index(page)
    num = yield from Blog.findNumber('count(id)')
    p = Page(num, page_index)
    if num == 0:
        return dict(page=p, blogs=())
    blogs = yield from Blog.findAll(orderBy='created_at desc', limit=(p.offset, p.limit))    #blogs为所有查询到的blog的dict
    return dict(page=p, blogs=blogs)
 
    #日志编辑页
@get('/manage/blogs/edit')
@asyncio.coroutine
def manage_blog_edit(*,id):  
    return {
        '__template__': 'manage_blog_edit.html',
        'id': id,
        'action': '/api/blogs/modify'
    }
    
     #提交评论
@post('/api/blogs/{id}/comments')
@asyncio.coroutine
def create_blog_comments(request,*,id,content):
    comment = Comment(user_id=request.__user__.id, user_name=request.__user__.name, user_image=request.__user__.image, content=content.strip(),blog_id=id)
    yield from comment.save()
    return comment
    
 
    #用户管理页
@get('/manage/users')
def manage_users(*, page='1'):
    return {
        '__template__': 'manage_users.html',
        'page_index': get_page_index(page)
    }    
    
   
    #获取某一页码的用户
@get('/api/users')
@asyncio.coroutine
def  api_users(*,page='1'):
    page_index=get_page_index(page)
    num = yield from User.findNumber('count(id)')
    p = Page(num , page_index)
    if num==0:
        return dict(page=p,users=())
    users = yield from User.findAll(orderBy='created_at desc', limit=(p.offset,p.limit))
    for user in users:                             #邮箱后两位隐藏
        first=user.email.split('@')[0]
        last=user.email.split('@')[1]
        first=first[0:-2]
        user.email=first+'**@'+last
    return dict(page=p, users=users)

    #添加管理员身份
@post('/api/admin/{id}/add')
@asyncio.coroutine
def add_admin(request,*,id):
    check_admin(request)
    logging.info('-------------------------------id %s'%id)
    user= yield from User.find(id)
    user.admin=1
    logging.info('success add admin======>%s'%user.name)
    yield from user.update()
    return user

    #移除管理员身份
@post('/api/admin/{id}/remove')
@asyncio.coroutine
def remove_admin(request,*,id):
    check_admin(request)
    logging.info('-------------------------------id %s'%id)
    user= yield from User.find(id)
    user.admin=0
    logging.info('success remove admin======>%s'%user.name)    
    yield from user.update()
    return user
 
    #评论管理页
@get('/manage/comments')
@asyncio.coroutine
def manage_comments(*,page='1'):
    return{
        '__template__':'manage_comments.html',
        'page_index': get_page_index(page)
    }

    #获取指定页码评论api
@get('/api/comments')
@asyncio.coroutine
def api_comments(*,page='1'):
    logging.info('-----------------------------------------------')
    page_index=get_page_index(page)
    num=yield from Comment.findNumber('count(id)')
    p=Page(num,page_index)
    if num==0:
        return dict(page=p,comments={})
    comments=yield from Comment.findAll(orderBy='created_at desc',limit=(p.offset,p.limit))
    for comment in comments:
        comment.time=time2date(comment.created_at)
    return dict(page=p,comments=comments)

    #删除评论api
@post('/api/comment/{id}/remove')
@asyncio.coroutine
def remove_comment(request,*,id):
    check_admin(request)
    comment=yield from Comment.find(id)
    yield from comment.remove()
    logging.info('success remove comment')
    return comment
        
    #