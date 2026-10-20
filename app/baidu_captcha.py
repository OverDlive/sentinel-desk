"""Bounded Baidu rotation handling over the app's existing loopback CDP session."""
import base64
import hashlib
import io
import json
import math
import random
import time
from urllib.parse import urlsplit

try:
    from .devtools import DevTools
except ImportError:
    from devtools import DevTools


STATE = r'''(() => {
 const host=location.hostname;
 if (!(host==='baidu.com'||host.endsWith('.baidu.com'))) return {outside:true};
 const img=document.querySelector('.passMod_spin-background');
 const knob=document.querySelector('.passMod_slide-btn');
 const track=document.querySelector('.passMod_slide-control');
 const box=el=>{if(!el)return null;const r=el.getBoundingClientRect();
   return r.width>0&&r.height>0?{x:r.x,y:r.y,width:r.width,height:r.height}:null};
 const message=document.querySelector('.passMod_spin-msg');
 let rotation=0;
 if(img){const transform=getComputedStyle(img).transform;if(transform!=='none'){
   const m=new DOMMatrix(transform);rotation=(Math.atan2(m.b,m.a)*180/Math.PI+360)%360;}}
 const refresh=document.querySelector('.passMod_dialog-footer-refresh')||
   Array.from(document.querySelectorAll('.passMod_verify-container *'))
   .find(el=>el.childElementCount===0&&el.textContent.trim()==='刷新'&&box(el));
 const grand=document.querySelector('.passMod_slide-grand');
 return {search:host==='www.baidu.com'&&location.pathname==='/s',
   ready:!!(img&&img.complete&&img.naturalWidth>20&&box(knob)&&box(track)),
   source:img?img.currentSrc:'',image:box(img),knob:box(knob),track:box(track),rotation,
   message:message?message.innerText.slice(0,180):'',refresh:box(refresh),
   verified:!!(grand&&grand.classList.contains('passMod_slide-grand-success')),
   webdriver:navigator.webdriver,device_scale:devicePixelRatio};
})()'''


def motion_points(start, finish, duration, rng=None):
    """A bounded smooth pointer movement; endpoints stay in the owned slider."""
    rng = rng or random.SystemRandom()
    steps = rng.randint(18, 30)
    durations = [rng.uniform(0.7, 1.3) for _ in range(steps)]
    total = sum(durations)
    phase, amplitude = rng.uniform(-math.pi, math.pi), rng.uniform(0.5, 1.8)
    points = []
    for index in range(1, steps + 1):
        t = index / steps
        eased = t * t * (3 - 2 * t)
        x = start[0] + (finish[0] - start[0]) * eased
        y = start[1] + (finish[1] - start[1]) * eased + amplitude * math.sin(math.pi * t) * math.sin(phase + t * 3)
        points.append((x, y, duration * durations[index - 1] / total))
    points[-1] = (finish[0], finish[1], points[-1][2])
    return points


class Page:
    def __init__(self, request):
        self.client = DevTools(request['endpoint'])
        info = self.client.call('Target.getTargetInfo', dict(targetId=request['target_id']))['targetInfo']
        host = urlsplit(info.get('url', '')).hostname or ''
        if host != 'baidu.com' and not host.endswith('.baidu.com'):
            self.client.close()
            raise ValueError('Not an owned Baidu page')
        self.session = self.client.call('Target.attachToTarget', dict(targetId=request['target_id'], flatten=True))['sessionId']
        self.responses, self.pending, self.requests = [], [], {}
        self.client.event_handler = self.record
        self.call('Page.enable')
        self.call('Network.enable')

    def call(self, method, params=None):
        return self.client.call(method, params or {}, session=self.session)

    def record(self, event):
        if event.get('method') == 'Network.requestWillBeSent':
            params = event.get('params', {})
            request = params.get('request', {})
            parts = urlsplit(request.get('url', ''))
            if parts.hostname == 'wappass.baidu.com' and parts.path == '/cap/c':
                try:
                    payload = json.loads(request.get('postData', '{}'))
                    if isinstance(payload, dict):
                        self.requests[params['requestId']] = {key:dict(present=bool(payload.get(key)),
                            length=len(payload[key]) if isinstance(payload.get(key), str) else 0)
                            for key in ('tk', 'ds', 'qrsign')}
                except (ValueError, TypeError):
                    pass
            return
        if event.get('method') != 'Network.responseReceived':
            return
        params = event.get('params', {})
        response = params.get('response', {})
        parts = urlsplit(response.get('url', ''))
        host = parts.hostname or ''
        if (host == 'baidu.com' or host.endswith('.baidu.com')) and parts.path.startswith('/cap/'):
            entry = dict(host=host, path=parts.path, http_status=response.get('status'))
            request_shape = self.requests.pop(params.get('requestId'), None)
            if request_shape is not None:
                entry['request_fields'] = request_shape
            self.responses.append(entry)
            if parts.path == '/cap/c':
                self.pending.append((params['requestId'], entry))

    def state(self):
        result = self.call('Runtime.evaluate', dict(expression=STATE, returnByValue=True))
        value = result.get('result', {}).get('value')
        if not isinstance(value, dict) or value.get('outside'):
            raise ValueError('Baidu frame is unavailable')
        return value

    def image(self, state):
        source = state['source']
        parts = urlsplit(source)
        host = parts.hostname or ''
        if parts.scheme != 'https' or not (host == 'baidu.com' or host.endswith('.baidu.com')):
            raise ValueError('Image is not a Baidu resource')
        tree = self.call('Page.getResourceTree')['frameTree']
        def find(node):
            if any(item.get('url') == source for item in node.get('resources', [])):
                return node['frame']['id']
            return next((value for child in node.get('childFrames', []) if (value := find(child))), None)
        frame_id = find(tree)
        if frame_id is None:
            raise ValueError('Image is not in the owned frame')
        resource = self.call('Page.getResourceContent', dict(frameId=frame_id, url=source))
        if not resource.get('base64Encoded') or len(resource['content']) > 1400000:
            raise ValueError('Invalid image resource')
        from PIL import Image, ImageDraw
        image = Image.open(io.BytesIO(base64.b64decode(resource['content'], validate=True))).convert('RGB').resize((152, 152))
        mask = Image.new('L', image.size)
        ImageDraw.Draw(mask).ellipse((0, 0, 152, 152), fill=255)
        image = Image.composite(image, Image.new('RGB', image.size, 'white'), mask)
        output = io.BytesIO()
        image.save(output, format='PNG')
        return output.getvalue()

    def screenshot(self):
        return base64.b64decode(self.call('Page.captureScreenshot', dict(format='png'))['data'])

    def mouse(self, kind, x, y, pressed=False):
        return self.call('Input.dispatchMouseEvent', dict(type=kind, x=x, y=y,
            button='left' if pressed or kind=='mouseReleased' else 'none',
            buttons=1 if pressed else 0, clickCount=1 if kind in ('mousePressed','mouseReleased') else 0,
            pointerType='mouse'))

    def move(self, start, finish, duration):
        points = motion_points(start, finish, duration)
        for x, y, delay in points:
            self.mouse('mouseMoved', x, y, True)
            time.sleep(delay)
        return len(points)

    def click(self, box):
        x, y = box['x'] + box['width']/2, box['y'] + box['height']/2
        self.mouse('mouseMoved', x, y)
        self.mouse('mousePressed', x, y, True)
        time.sleep(.08)
        self.mouse('mouseReleased', x, y)

    def read_verification(self, fields):
        pending, self.pending = self.pending, []
        for request_id, entry in pending:
            try:
                result = self.call('Network.getResponseBody', dict(requestId=request_id))
                body = result.get('body', '')
                if result.get('base64Encoded'):
                    body = base64.b64decode(body).decode('utf-8')
                if len(body) < 65536:
                    entry.update(fields(body))
                    try:
                        payload = json.loads(body)
                        if isinstance(payload.get('data'), dict):
                            entry['gate_success'] = bool(payload['data'].get('s'))
                    except (ValueError, AttributeError):
                        pass
            except Exception:
                self.pending.append((request_id, entry))

    def close(self):
        try:
            self.client.call('Target.detachFromTarget', dict(sessionId=self.session))
        finally:
            self.client.close()


def solve(models, request, evidence_image, evidence_json, fields):
    page = Page(request)
    events, previous_source = [], None
    deadline = time.monotonic() + 80
    result = None
    try:
        for attempt in range(3):
            ready_deadline = min(deadline, time.monotonic() + 15)
            while time.monotonic() < ready_deadline:
                state = page.state()
                if state['search']:
                    result = dict(status='navigation_resumed', events=events)
                    break
                if state['ready'] and state['source'] != previous_source:
                    break
                time.sleep(.25)
            else:
                result = dict(status='challenge_not_loaded', events=events, reason='새 회전 CAPTCHA가 준비되지 않았습니다.')
                break
            if result is not None:
                break
            data = page.image(state)
            previous_source = state['source']
            evidence_image(request, f'baidu-{attempt}.png', data)
            if request.get('artifacts'):
                evidence_image(request, f'baidu-{attempt}-before.png', page.screenshot())
            strategy = ('consensus', 'rotnet', 'convnext')[attempt]
            prediction = models.baidu(data, strategy=strategy)
            prediction.update(attempt=attempt, controller='direct_cdp', webdriver=state['webdriver'],
                image_source='browser_cached_payload', image_sha256=hashlib.sha256(data).hexdigest(), submitted=False)
            events.append(prediction)
            # Discard a prediction if the server replaced the image during inference.
            current = page.state()
            if current['source'] != previous_source:
                prediction['discarded'] = 'image_changed_during_inference'
                previous_source = None
                continue
            knob, rail = state['knob'], state['track']
            travel = rail['width'] - knob['width']
            if travel <= 0:
                raise ValueError('Invalid slider range')
            x, y = knob['x'] + knob['width']/2, knob['y'] + knob['height']/2
            distance = prediction['clockwise_correction']/360 * travel
            probe = min(30, distance/2)
            page.mouse('mouseMoved', x, y)
            page.mouse('mousePressed', x, y, True)
            pointer_x, pointer_y = x, y
            try:
                steps = page.move((x,y), (x+probe,y), random.uniform(.22,.38))
                pointer_x = x + probe
                time.sleep(.16)
                delta = (page.state()['rotation'] - state['rotation']) % 360
                measured = probe*360/delta if probe >= 2 and 1 < delta < 180 else travel
                if not .7*travel < measured < 1.3*travel:
                    measured = travel
                distance = min(travel, max(0, prediction['clockwise_correction']/360 * measured))
                steps += page.move((x+probe,y), (x+distance,y), random.uniform(.9,1.5))
                pointer_x = x + distance
                time.sleep(.25)
                target = (state['rotation'] + prediction['clockwise_correction']) % 360
                for _ in range(2):
                    aligned = page.state()
                    error = (target-aligned['rotation']+180)%360-180
                    if abs(error) <= 1.8:
                        break
                    distance = min(travel, max(0, distance+error/360*measured))
                    page.mouse('mouseMoved', x+distance, y, True)
                    pointer_x = x + distance
                    time.sleep(random.uniform(.16,.3))
                aligned = page.state()
                prediction.update(travel=travel, measured_travel=measured, drag_distance=distance,
                    applied_rotation=aligned['rotation'], rotation_error=(target-aligned['rotation']+180)%360-180,
                    trajectory_steps=steps)
                if request.get('artifacts'):
                    evidence_image(request, f'baidu-{attempt}-aligned.png', page.screenshot())
            finally:
                page.mouse('mouseReleased', pointer_x, pointer_y)
            prediction['submitted'] = True
            # Poll instead of assuming that releasing the slider means success.
            settled = min(deadline, time.monotonic() + 8)
            while time.monotonic() < settled:
                state = page.state()
                page.read_verification(fields)
                if state['verified']:
                    prediction['widget_success_observed'] = True
                if state['search']:
                    result = dict(status='navigation_resumed', events=events)
                    break
                time.sleep(.25)
            page.read_verification(fields)
            prediction['site_message'] = state.get('message','')
            if request.get('artifacts'):
                evidence_image(request, f'baidu-{attempt}-after.png', page.screenshot())
            if result is not None:
                break
            if time.monotonic() >= deadline or any(term in state.get('message','') for term in ('频繁','稍后再试')):
                break
            if state['source'] == previous_source and state.get('refresh'):
                page.click(state['refresh'])
                time.sleep(.8)
        if result is None:
            widget_passed = any(item.get('widget_success_observed') for item in events)
            gate_denied = any(item.get('gate_success') is False for item in page.responses)
            status = 'widget_verified_access_denied' if widget_passed and gate_denied else 'navigation_timeout' if widget_passed else 'server_rejected'
            reason = 'CAPTCHA 위젯 성공 표시 후 Baidu 검색 사이트의 후속 승인이 거부되었습니다.' if gate_denied else 'CAPTCHA 처리 후 원래 검색으로 복귀하지 못했습니다.'
            result = dict(status=status, events=events, reason=reason)
        page.read_verification(fields)
        result.update(verification_responses=page.responses[-25:], controller='direct_cdp')
        evidence_json(request, 'worker-report.json', result)
        return result
    finally:
        page.close()
