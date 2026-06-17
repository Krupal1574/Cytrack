import os
import datetime
from django.shortcuts import render
import requests
from dotenv import load_dotenv
from collections import defaultdict
import folium
from iso3166 import countries_by_name
from cyber.settings import BASE_DIR
from folium.plugins import HeatMap


# Load environment variables
load_dotenv(os.path.join(BASE_DIR, '.env'))
OTX_API_KEY = os.getenv('OTX_API_KEY')

# More comprehensive country → lat/lon mapping
COUNTRY_LATLON = {
    'AF': [33.9391, 67.7100], 'AL': [41.1533, 20.1683], 'DZ': [28.0339, 1.6596],
    'AD': [42.5462, 1.6016], 'AO': [-11.2027, 17.8739], 'AG': [17.0608, -61.7964],
    'AR': [-38.4161, -63.6167], 'AM': [40.0691, 45.0382], 'AU': [-25.2744, 133.7751],
    'AT': [47.5162, 14.5501], 'AZ': [40.1431, 47.5769], 'BS': [25.0343, -77.3963],
    'BH': [26.0667, 50.5577], 'BD': [23.6850, 90.3563], 'BB': [13.1939, -59.5432],
    'BY': [53.7098, 27.9534], 'BE': [50.5039, 4.4699], 'BZ': [17.1899, -88.4976],
    'BJ': [9.3077, 2.3158], 'BT': [27.5142, 90.4336], 'BO': [-16.2902, -63.5887],
    'BA': [43.9159, 17.6791], 'BW': [-22.3285, 24.6849], 'BR': [-14.2350, -51.9253],
    'BN': [4.5353, 114.7277], 'BG': [42.7339, 25.4858], 'BF': [12.2383, -1.5616],
    'BI': [-3.3731, 29.9189], 'KH': [12.5657, 104.9910], 'CM': [7.3697, 12.3547],
    'CA': [56.1304, -106.3468], 'CV': [16.5388, -23.0418], 'CF': [6.6111, 20.9394],
    'TD': [15.4542, 18.7322], 'CL': [-35.6751, -71.5430], 'CN': [35.8617, 104.1954],
    'CO': [4.5709, -74.2973], 'KM': [-11.8750, 43.8722], 'CD': [-4.0383, 21.7587],
    'CG': [-0.2280, 15.8277], 'CR': [9.7489, -83.7534], 'HR': [45.1000, 15.2000],
    'CU': [21.5218, -77.7812], 'CY': [35.1264, 33.4299], 'CZ': [49.8175, 15.4730],
    'DK': [56.2639, 9.5018], 'DJ': [11.8251, 42.5903], 'DM': [15.4149, -61.3709],
    'DO': [18.7357, -70.1627], 'EC': [-1.8312, -78.1834], 'EG': [26.8206, 30.8025],
    'SV': [13.7942, -88.8965], 'GQ': [1.6508, 10.2679], 'ER': [15.1794, 39.7823],
    'EE': [58.5953, 25.0136], 'ET': [9.1450, 40.4897], 'FJ': [-17.7134, 178.0650],
    'FI': [61.9241, 25.7482], 'FR': [46.2276, 2.2137], 'GA': [-0.8037, 11.6094],
    'GM': [13.4432, -15.3101], 'GE': [42.3154, 43.3569], 'DE': [51.1657, 10.4515],
    'GH': [7.9465, -1.0232], 'GR': [39.0742, 21.8243], 'GD': [12.1165, -61.6790],
    'GT': [15.7835, -90.2308], 'GN': [9.9456, -9.6966], 'GW': [11.8037, -15.1804],
    'GY': [4.8604, -58.9302], 'HT': [18.9712, -72.2852], 'HN': [13.7942, -88.8965],
    'HU': [47.1625, 19.5033], 'IS': [64.9631, -19.0208], 'IN': [20.5937, 78.9629],
    'ID': [-0.7893, 113.9213], 'IR': [32.4279, 53.6880], 'IQ': [33.2232, 43.6793],
    'IE': [53.4129, -8.2439], 'IL': [31.0461, 34.8516], 'IT': [41.8719, 12.5674],
    'JM': [18.1096, -77.2975], 'JP': [36.2048, 138.2529], 'JO': [30.5852, 36.2384],
    'KZ': [48.0196, 66.9237], 'KE': [-0.0236, 37.9062], 'KI': [1.8709, -157.3630],
    'KP': [40.3399, 127.5101], 'KR': [35.9078, 127.7669], 'KW': [29.3117, 47.4818],
    'KG': [41.2044, 74.7661], 'LA': [19.8563, 102.4955], 'LV': [56.8796, 24.6032],
    'LB': [33.8547, 35.8623], 'LS': [-29.6099, 28.2336], 'LR': [6.4281, -9.4295],
    'LY': [26.3351, 17.2283], 'LI': [47.1660, 9.5554], 'LT': [55.1694, 23.8813],
    'LU': [49.8153, 6.1296], 'MK': [41.6086, 21.7453], 'MG': [-18.7669, 46.8691],
    'MW': [-13.2543, 34.3015], 'MY': [4.2105, 101.9758], 'MV': [3.2028, 73.2207],
    'ML': [17.5707, -3.9962], 'MT': [35.9375, 14.3754], 'MH': [7.1315, 171.1845],
    'MR': [21.0079, -10.9408], 'MU': [-20.3484, 57.5522], 'MX': [23.6345, -102.5528],
    'FM': [7.4256, 150.5508], 'MD': [47.4116, 28.3699], 'MC': [43.7384, 7.4246],
    'MN': [46.8625, 103.8467], 'ME': [42.7087, 19.3744], 'MA': [31.7917, -7.0926],
    'MZ': [-18.6657, 35.5296], 'MM': [21.9162, 95.9560], 'NA': [-22.9576, 18.4904],
    'NR': [-0.5228, 166.9315], 'NP': [28.3949, 84.1240], 'NL': [52.1326, 5.2913],
    'NZ': [-40.9006, 174.8860], 'NI': [12.8654, -85.2072], 'NE': [17.6078, 8.0817],
    'NG': [9.0820, 8.6753], 'NO': [60.4720, 8.4689], 'OM': [21.4735, 55.9754],
    'PK': [30.3753, 69.3451], 'PW': [7.5150, 134.5825], 'PA': [8.5379, -80.7821],
    'PG': [-6.3149, 143.9555], 'PY': [-23.4425, -58.4438], 'PE': [-9.1900, -75.0152],
    'PH': [13.4103, 122.5600], 'PL': [51.9194, 19.1451], 'PT': [39.3999, -8.2245],
    'QA': [25.3548, 51.1839], 'RO': [45.9432, 24.9668], 'RU': [61.5240, 105.3188],
    'RW': [-1.9403, 29.8739], 'KN': [17.3578, -62.7829], 'LC': [13.9094, -60.9789],
    'VC': [12.9843, -61.2872], 'WS': [-13.7590, -172.1046], 'SM': [43.9333, 12.4500],
    'ST': [0.1864, 6.6131], 'SA': [23.8859, 45.0792], 'SN': [14.4974, -14.4524],
    'RS': [44.0165, 21.0059], 'SC': [-4.6796, 55.4920], 'SL': [8.4606, -11.7799],
    'SG': [1.3521, 103.8198], 'SK': [48.6690, 19.6990], 'SI': [46.1512, 14.9955],
    'SB': [-9.6457, 160.1562], 'SO': [5.1521, 46.1996], 'ZA': [-30.5595, 22.9375],
    'SS': [7.8627, 29.6949], 'ES': [40.4637, -3.7492], 'LK': [7.8731, 80.7718],
    'SD': [12.8628, 30.2176], 'SR': [3.9193, -56.0278], 'SZ': [-26.5225, 31.4659],
    'SE': [60.1282, 18.6435], 'CH': [46.8182, 8.2275], 'SY': [34.8021, 38.9968],
    'TW': [23.6978, 120.9605], 'TJ': [38.8610, 71.2761], 'TZ': [-6.3690, 34.8888],
    'TH': [15.8700, 100.9925], 'TL': [-8.8742, 125.7275], 'TG': [8.6195, 0.8248],
    'TO': [-21.1789, -175.1982], 'TT': [10.6918, -61.2225], 'TN': [33.8869, 9.5375],
    'TR': [38.9637, 35.2433], 'TM': [38.9697, 59.5563], 'UG': [1.3733, 32.2903],
    'UA': [48.3794, 31.1656], 'AE': [23.4241, 53.8478], 'GB': [55.3781, -3.4360],
    'US': [37.0902, -95.7129], 'UY': [-32.5228, -55.7658], 'UZ': [41.3775, 64.5853],
    'VU': [-15.3767, 166.9592], 'VA': [41.9029, 12.4534], 'VE': [6.4238, -66.5897],
    'VN': [14.0583, 108.2772], 'YE': [15.5527, 48.5164], 'ZM': [-13.1339, 27.8493],
    'ZW': [-19.0154, 29.1549],
    'HK': [22.3193, 114.1694], 'XK': [42.6026, 20.9020], 'GLOBAL': [0, 0]
}


# Map demonyms and names to ISO country codes
def extract_country(text):
    text = text.lower()
    for name, country in countries_by_name.items():
        if name.lower() in text:
            return country.alpha2
    demonyms = {
    'afghan': 'AF', 'albanian': 'AL', 'algerian': 'DZ', 'american': 'US', 'andorran': 'AD',
    'angolan': 'AO', 'argentine': 'AR', 'armenian': 'AM', 'australian': 'AU', 'austrian': 'AT',
    'azerbaijani': 'AZ', 'bahamian': 'BS', 'bahraini': 'BH', 'bangladeshi': 'BD', 'barbadian': 'BB',
    'belarusian': 'BY', 'belgian': 'BE', 'belizean': 'BZ', 'beninese': 'BJ', 'bhutanese': 'BT',
    'bolivian': 'BO', 'bosnian': 'BA', 'botswanan': 'BW', 'brazilian': 'BR', 'british': 'GB',
    'bruneian': 'BN', 'bulgarian': 'BG', 'burkinabe': 'BF', 'burmese': 'MM', 'burundian': 'BI',
    'cambodian': 'KH', 'cameroonian': 'CM', 'canadian': 'CA', 'cape verdean': 'CV', 'central african': 'CF',
    'chadian': 'TD', 'chilean': 'CL', 'chinese': 'CN', 'colombian': 'CO', 'comoran': 'KM',
    'congolese': 'CG', 'congolese (drc)': 'CD', 'costa rican': 'CR', 'croatian': 'HR', 'cuban': 'CU',
    'cypriot': 'CY', 'czech': 'CZ', 'danish': 'DK', 'djiboutian': 'DJ', 'dominican': 'DO',
    'dutch': 'NL', 'ecuadorian': 'EC', 'egyptian': 'EG', 'emirati': 'AE', 'english': 'GB',
    'equatorial guinean': 'GQ', 'eritrean': 'ER', 'estonian': 'EE', 'ethiopian': 'ET', 'fijian': 'FJ',
    'finnish': 'FI', 'french': 'FR', 'gabonese': 'GA', 'gambian': 'GM', 'georgian': 'GE',
    'german': 'DE', 'ghanaian': 'GH', 'greek': 'GR', 'grenadian': 'GD', 'guatemalan': 'GT',
    'guinean': 'GN', 'guinean-bissauan': 'GW', 'guyanese': 'GY', 'haitian': 'HT', 'honduran': 'HN',
    'hungarian': 'HU', 'icelandic': 'IS', 'indian': 'IN', 'indonesian': 'ID', 'iranian': 'IR',
    'iraqi': 'IQ', 'irish': 'IE', 'israeli': 'IL', 'italian': 'IT', 'ivorian': 'CI',
    'jamaican': 'JM', 'japanese': 'JP', 'jordanian': 'JO', 'kazakh': 'KZ', 'kenyan': 'KE',
    'kittitian': 'KN', 'kuwaiti': 'KW', 'kyrgyz': 'KG', 'laotian': 'LA', 'latvian': 'LV',
    'lebanese': 'LB', 'liberian': 'LR', 'libyan': 'LY', 'lithuanian': 'LT', 'luxembourgish': 'LU',
    'macedonian': 'MK', 'malagasy': 'MG', 'malawian': 'MW', 'malaysian': 'MY', 'maldivian': 'MV',
    'malian': 'ML', 'maltese': 'MT', 'marshallese': 'MH', 'mauritanian': 'MR', 'mauritian': 'MU',
    'mexican': 'MX', 'micronesian': 'FM', 'moldovan': 'MD', 'monacan': 'MC', 'mongolian': 'MN',
    'montenegrin': 'ME', 'moroccan': 'MA', 'mozambican': 'MZ', 'namibian': 'NA', 'nauruan': 'NR',
    'nepalese': 'NP', 'new zealander': 'NZ', 'nicaraguan': 'NI', 'nigerian': 'NG', 'nigerien': 'NE',
    'north korean': 'KP', 'northern irish': 'GB', 'norwegian': 'NO', 'omani': 'OM', 'pakistani': 'PK',
    'palauan': 'PW', 'palestinian': 'PS', 'panamanian': 'PA', 'papua new guinean': 'PG', 'paraguayan': 'PY',
    'peruvian': 'PE', 'philippine': 'PH', 'polish': 'PL', 'portuguese': 'PT', 'qatari': 'QA',
    'romanian': 'RO', 'russian': 'RU', 'rwandan': 'RW', 'saint lucian': 'LC', 'salvadoran': 'SV',
    'sammarinese': 'SM', 'samoan': 'WS', 'saudi': 'SA', 'scottish': 'GB', 'senegalese': 'SN',
    'serbian': 'RS', 'seychellois': 'SC', 'sierra leonean': 'SL', 'singaporean': 'SG', 'slovak': 'SK',
    'slovenian': 'SI', 'solomon islander': 'SB', 'somali': 'SO', 'south african': 'ZA', 'south korean': 'KR',
    'south sudanese': 'SS', 'spanish': 'ES', 'sri lankan': 'LK', 'sudanese': 'SD', 'surinamese': 'SR',
    'swazi': 'SZ', 'swedish': 'SE', 'swiss': 'CH', 'syrian': 'SY', 'taiwanese': 'TW',
    'tajik': 'TJ', 'tanzanian': 'TZ', 'thai': 'TH', 'togolese': 'TG', 'tongan': 'TO',
    'trinidadian': 'TT', 'tunisian': 'TN', 'turkish': 'TR', 'turkmen': 'TM', 'tuvaluan': 'TV',
    'ugandan': 'UG', 'ukrainian': 'UA', 'uruguayan': 'UY', 'uzbek': 'UZ', 'venezuelan': 'VE',
    'vietnamese': 'VN', 'welsh': 'GB', 'yemeni': 'YE', 'zambian': 'ZM', 'zimbabwean': 'ZW',

    # Common shortcuts
    'usa': 'US', 'us': 'US', 'uk': 'GB', 'u.s.': 'US', 'u.k.': 'GB', 'global': 'GLOBAL',
    'world': 'GLOBAL', 'international': 'GLOBAL'
    }

    for word, code in demonyms.items():
        if word in text:
            return code
    return 'GLOBAL'



def dashboard(request):
    news_items = []
    heatmap_filename = None
    debug_info = {}  # Accumulates debug metadata (not exposed to template)

    if not OTX_API_KEY:
        news_items.append({'title': 'Error', 'description': 'OTX API key not found'})
        return render(request, 'dashboard/dashboard.html', {'newsdata_news': news_items})

    url = 'https://otx.alienvault.com/api/v1/pulses/subscribed?limit=100'
    headers = {'X-OTX-API-KEY': OTX_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        debug_info['api_status'] = response.status_code

        if response.status_code != 200:
            news_items.append({'title': 'Error', 'description': f'API error: {response.status_code}'})
            return render(request, 'dashboard/dashboard.html', {'newsdata_news': news_items})

        data = response.json()
        pulses = data.get('results', [])
        now = datetime.datetime.utcnow()
        two_months_ago = now - datetime.timedelta(days=60)

        seen_ids = set()
        country_articles = defaultdict(list)
        heatmap_points = []

        for pulse in pulses:
            pulse_id = pulse.get('id')
            if not pulse_id or pulse_id in seen_ids:
                continue
            seen_ids.add(pulse_id)

            title = pulse.get('name', 'No Title')
            description = pulse.get('description', '')
            tags_list = pulse.get('tags', [])
            tags = ', '.join(tags_list)
            created_str = pulse.get('created', '')
            author = pulse.get('author_name', '')
            link = f"https://otx.alienvault.com/pulse/{pulse_id}"

            try:
                created_dt = datetime.datetime.strptime(created_str[:19], '%Y-%m-%dT%H:%M:%S')
            except Exception:
                created_dt = None

            if created_dt and (now - created_dt).days <= 7:
                news_items.append({
                    'title': title,
                    'description': description[:200] + ('...' if len(description) > 200 else ''),
                    'created': created_dt.strftime('%Y-%m-%d %H:%M'),
                    'author': author,
                    'tags': tags,
                    'link': link,
                    'category': tags_list,
                    'pubDate': created_dt.strftime('%Y-%m-%d %H:%M'),
                    'source': author or 'AlienVault OTX'
                })

            # Extract country for heatmap
            if created_dt and created_dt >= two_months_ago:
                combined_text = f"{title} {description} {tags}"
                country = extract_country(combined_text)
                coords = COUNTRY_LATLON.get(country)
                if not coords or coords == [0, 0]:
                    continue
                country_articles[country].append({
                    'title': title,
                    'desc': description[:100],
                    'link': link
                })
                heatmap_points.append(coords)

        # HEATMAP
        # dark themed map
        m = folium.Map(
            location=[20, 0],
            zoom_start=2,
            tiles=None, 
            max_bounds=True,
            min_zoom=2,
            max_zoom=6,
            prefer_canvas=True,
            no_wrap=True,
            control_scale=True
        )

        folium.TileLayer(
            tiles='https://server.arcgisonline.com/ArcGIS/rest/services/World_Physical_Map/MapServer/tile/{z}/{y}/{x}',
            attr='Esri',
            name='Dark Land Light Ocean',
            overlay=False,
            control=False
        ).add_to(m)

        if heatmap_points:
            # bullet color style
            gradient = {
                0.2: "#f30f0f",   
                0.5: "#b11e1e",   
                0.8: "#C70505",   
                1.0: "#FA0303"    
            }
        
            HeatMap(
                heatmap_points,
                radius=15,
                blur=12,
                min_opacity=0.5,
                gradient=gradient
            ).add_to(m)
            debug_info['heatmap_saved'] = True

        for country, articles in country_articles.items():
            coords = COUNTRY_LATLON.get(country)
            if not coords:
                continue
            popup_html = """
                <div style='max-height:300px; overflow:auto; font-size:13px;
                           background: rgba(0,0,0,0.8); color: #fff;
                           padding: 15px; border-radius: 8px;
                           backdrop-filter: blur(10px);'>
            """
            for item in articles:
                popup_html += f"""
                    <div style='margin-bottom: 15px; border-bottom: 1px solid rgba(255,255,255,0.1);
                               padding-bottom: 10px;'>
                        <h4 style='color: #00ffcc; margin: 0 0 8px 0;'>{item['title']}</h4>
                        <p style='color: #ccc; margin: 5px 0;'>{item['desc']}</p>
                        <a href='{item['link']}' target='_blank'
                           style='color: #3498db; text-decoration: none;
                                  display: inline-block; margin-top: 5px;
                                  transition: color 0.3s ease;'
                           onmouseover="this.style.color='#00ffcc'"
                           onmouseout="this.style.color='#3498db'">
                            Read more →
                        </a>
                    </div>
                """
            popup_html += "</div>"
            # Custom marker icon
            custom_icon = folium.DivIcon(
                html=f"""
                    <div style='background-color: rgba(0,255,204,0.2);
                              width: 12px; height: 12px;
                              border-radius: 50%;
                              border: 2px solid #00ffcc;
                              box-shadow: 0 0 15px #00ffcc;'>
                    </div>
                """,
                icon_size=(12, 12),
            )

            # Add marker with custom styling
            marker = folium.Marker(
                location=coords,
                popup=folium.Popup(popup_html, max_width=400),
                icon=custom_icon,
                tooltip=f"<div style='font-size: 14px; color: #00ffcc;'>{len(articles)} incidents reported</div>"
            )
            marker.add_to(m)

            # Add pulse animation circle
            folium.Circle(
                location=coords,
                radius=100000,  # 100km
                color='#00ffcc',
                fill=True,
                fillColor='#00ffcc',
                fillOpacity=0.1,
                weight=1,
                className='pulse-circle'
            ).add_to(m)

        if heatmap_points:
            # Add custom CSS for animations
            m.get_root().header.add_child(folium.Element("""
                <style>
                    .pulse-circle {
                        animation: pulse 2s infinite;
                    }
                    @keyframes pulse {
                        0% { opacity: 0.4; }
                        50% { opacity: 0.1; }
                        100% { opacity: 0.4; }
                    }
                    .leaflet-popup-content-wrapper {
                        background: rgba(0,0,0,0.8) !important;
                        backdrop-filter: blur(10px);
                        border: 1px solid rgba(255,255,255,0.1);
                    }
                    .leaflet-popup-tip {
                        background: rgba(0,0,0,0.8) !important;
                    }
                </style>
            """))

            # Fit bounds with smooth animation
            m.fit_bounds(heatmap_points, padding=(50, 50))
            heatmap_filename = 'global_cybercrime_heatmap.html'
            heatmap_path = os.path.join(BASE_DIR, 'static', 'plots', heatmap_filename)
            os.makedirs(os.path.dirname(heatmap_path), exist_ok=True)
            m.save(heatmap_path)

    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error('Dashboard OTX fetch failed: %s', e, exc_info=True)
        news_items.append({'title': 'Data Unavailable', 'description': 'Threat intelligence is temporarily unavailable.'})

    return render(request, 'dashboard/dashboard.html', {
        'newsdata_news': news_items,
        'heatmap_filename': heatmap_filename,
        'heatmap_path': f"/static/plots/{heatmap_filename}" if heatmap_filename else None,
    })


def base(request):
    return render(request, 'dashboard/base.html')

def about(request):
    return render(request, 'dashboard/about.html')

def contact(request):
    return render(request, 'dashboard/contact.html')
