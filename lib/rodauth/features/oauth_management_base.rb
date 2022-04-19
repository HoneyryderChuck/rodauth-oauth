# frozen_string_literal: true

module Rodauth
  Feature.define(:oauth_management_base, :OauthManagementBase) do
    depends :oauth_base

    button "Previous", "oauth_management_pagination_previous"
    button "Next", "oauth_management_pagination_next"

    def oauth_management_pagination_links(paginated_ds)
      html = +'<nav aria-label="Pagination"><ul class="pagination">'
      html << oauth_management_pagination_link(paginated_ds.prev_page, label: oauth_management_pagination_previous_button)
      html << oauth_management_pagination_link(paginated_ds.current_page - 1) unless paginated_ds.first_page?
      html << oauth_management_pagination_link(paginated_ds.current_page, label: paginated_ds.current_page, current: true)
      html << oauth_management_pagination_link(paginated_ds.current_page + 1) unless paginated_ds.last_page?
      html << oauth_management_pagination_link(paginated_ds.next_page, label: oauth_management_pagination_next_button)
      html << "</ul></nav>"
    end

    def oauth_management_pagination_link(page, label: page, current: false, classes: "")
      classes += " disabled" if current || !page
      classes += " active" if current
      if page
        params = request.GET.merge("page" => page).map do |k, v|
          v ? "#{CGI.escape(String(k))}=#{CGI.escape(String(v))}" : CGI.escape(String(k))
        end.join("&")

        href = "#{request.path}?#{params}"

        <<-HTML
          <li class="page-item #{classes}" #{'aria-current="page"' if current}>
            <a class="page-link" href="#{href}" tabindex="-1" aria-disabled="#{current || !page}">
              #{label}
            </a>
          </li>
        HTML
      else
        <<-HTML
          <li class="page-item #{classes}">
            <span class="page-link">
              #{label}
              #{'<span class="sr-only">(current)</span>' if current}
            </span>
          </li>
        HTML
      end
    end

    def post_configure
      super
      db.extension :pagination
    end

    private

    def per_page_param(default_per_page)
      per_page = param_or_nil("per_page")

      return default_per_page unless per_page

      per_page = per_page.to_i

      return default_per_page if per_page <= 0

      [per_page, default_per_page].min
    end
  end
end
