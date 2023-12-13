document.addEventListener('DOMContentLoaded', (event) => {
    let container = document.getElementById('dependencia-container-{{ loop.index }}');
    let images = container.getElementsByClassName('dependencia-image');
    let totalWidth = 0;
    for (let image of images) {
        totalWidth += image.offsetWidth;
    }
    if (totalWidth > container.offsetWidth) {
        // Convertir a carrusel
        container.classList.add('carousel', 'slide');
        for (let image of images) {
            let item = document.createElement('div');
            item.className = 'carousel-item';
            item.appendChild(image);
            container.appendChild(item);
        }
        container.firstElementChild.classList.add('active');
        // Agregar controles del carrusel aquí si es necesario
    }
});